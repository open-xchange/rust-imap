//! Adds support for the IMAP IDLE command specificed in [RFC
//! 2177](https://tools.ietf.org/html/rfc2177).

use client::Session;
use error::{Error, Result};
use mio::*;
use native_tls::TlsStream;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::os::unix::io::{AsRawFd, RawFd};

/// `Handle` allows a client to block waiting for changes to the remote mailbox.
///
/// The handle blocks using the [`IDLE` command](https://tools.ietf.org/html/rfc2177#section-3)
/// specificed in [RFC 2177](https://tools.ietf.org/html/rfc2177) until the underlying server state
/// changes in some way. While idling does inform the client what changes happened on the server,
/// this implementation will currently just block until _anything_ changes, and then notify the
///
/// Note that the server MAY consider a client inactive if it has an IDLE command running, and if
/// such a server has an inactivity timeout it MAY log the client off implicitly at the end of its
/// timeout period.  Because of that, clients using IDLE are advised to terminate the IDLE and
/// re-issue it at least every 29 minutes to avoid being logged off. [`Handle::wait_keepalive`]
/// does this. This still allows a client to receive immediate mailbox updates even though it need
/// only "poll" at half hour intervals.
///
/// As long as a [`Handle`] is active, the mailbox cannot be otherwise accessed.
#[derive(Debug)]
pub struct Handle<'a, T: Read + Write> {
    session: &'a mut Session<T>,
    keepalive: Duration,
    done: bool,
    poll: Poll,
}

/// Must be implemented for a transport in order for a `Session` using that transport to support
/// operations with timeouts.
///
/// Examples of where this is useful is for `Handle::wait_keepalive` and
/// `Handle::wait_timeout`.
pub trait SetReadTimeout {
    /// Set the timeout for subsequent reads to the given one.
    ///
    /// If `timeout` is `None`, the read timeout should be removed.
    ///
    /// See also `std::net::TcpStream::set_read_timeout`.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()>;
}

/// Must be implemented for a transport in order for a `Session` using that
/// transport to support interruptible operations.
///
/// Examples of where this is usedful is for `Handle::wait_interruptible`.
pub trait Async {
    /// The concrete type of the Evented implementation returned by `get_evented`.
    type Ev: Evented;

    /// Returns an implementation of Evented for async IO.
    fn get_evented(&self) -> Self::Ev;

    /// Set the transport to be blocking (the default, or when `nonblocking` is
    /// `false`) or nonblocking (when `nonblocking` is `true`).
    ///
    /// See also `std::net::TcpStream::set_nonblocking`.
    fn set_nonblocking(&self, nonblocking: bool) -> Result<()>;
}

impl<'a, T: Read + Write> Handle<'a, T> {
    pub(crate) fn make(session: &'a mut Session<T>) -> Result<Self> {
        let mut h = Handle {
            session,
            keepalive: Duration::from_secs(29 * 60),
            done: false,
            poll: Poll::new()?,
        };
        h.init()?;
        Ok(h)
    }

    fn init(&mut self) -> Result<()> {
        // https://tools.ietf.org/html/rfc2177
        //
        // The IDLE command takes no arguments.
        self.session.run_command("IDLE")?;

        // A tagged response will be sent either
        //
        //   a) if there's an error, or
        //   b) *after* we send DONE
        let mut v = Vec::new();
        self.session.readline(&mut v)?;
        if v.starts_with(b"+") {
            self.done = false;
            return Ok(());
        }

        self.session.read_response_onto(&mut v)?;
        // We should *only* get a continuation on an error (i.e., it gives BAD or NO).
        unreachable!();
    }

    fn terminate(&mut self) -> Result<()> {
        if !self.done {
            self.done = true;
            self.session.write_line(b"DONE")?;
            self.session.read_response().map(|_| ())
        } else {
            Ok(())
        }
    }

    /// Internal helper that doesn't consume self.
    ///
    /// This is necessary so that we can keep using the inner `Session` in `wait_keepalive`.
    fn wait_inner(&mut self) -> Result<()> {
        let mut v = Vec::new();
        match self.session.readline(&mut v).map(|_| ()) {
            Err(Error::Io(ref e))
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                // we need to refresh the IDLE connection
                self.terminate()?;
                self.init()?;
                self.wait_inner()
            }
            r => r,
        }
    }

    /// Block until the selected mailbox changes.
    pub fn wait(mut self) -> Result<()> {
        self.wait_inner()
    }

    /// Set the keep-alive interval to use when `wait_keepalive` is called.
    ///
    /// The interval defaults to 29 minutes as dictated by RFC 2177.
    pub fn set_keepalive(&mut self, interval: Duration) {
        self.keepalive = interval;
    }
}

impl<'a, T: SetReadTimeout + Read + Write> Handle<'a, T> {
    /// Block until the selected mailbox changes.
    ///
    /// This method differs from [`Handle::wait`] in that it will periodically refresh the IDLE
    /// connection, to prevent the server from timing out our connection. The keepalive interval is
    /// set to 29 minutes by default, as dictated by RFC 2177, but can be changed using
    /// [`Handle::set_keepalive`].
    ///
    /// This is the recommended method to use for waiting.
    pub fn wait_keepalive(self) -> Result<()> {
        // The server MAY consider a client inactive if it has an IDLE command
        // running, and if such a server has an inactivity timeout it MAY log
        // the client off implicitly at the end of its timeout period.  Because
        // of that, clients using IDLE are advised to terminate the IDLE and
        // re-issue it at least every 29 minutes to avoid being logged off.
        // This still allows a client to receive immediate mailbox updates even
        // though it need only "poll" at half hour intervals.
        let keepalive = self.keepalive;
        self.wait_timeout(keepalive)
    }

    /// Block until the selected mailbox changes, or until the given amount of time has expired.
    pub fn wait_timeout(mut self, timeout: Duration) -> Result<()> {
        self.session
            .stream
            .get_mut()
            .set_read_timeout(Some(timeout))?;
        let res = self.wait_inner();
        let _ = self.session.stream.get_mut().set_read_timeout(None).is_ok();
        res
    }
}

/// A generic signal used to terminate a `wait_interruptible`.
#[derive(Debug)]
pub struct Signal {
    registration: Registration,
    set_readiness: SetReadiness,
}

impl Signal {
    fn new() -> Signal {
        let (registration, set_readiness) = Registration::new2();
        Signal {
            registration,
            set_readiness,
        }
    }

    /// Send the signal, usually to terminate a `wait_interruptible`.
    pub fn signal(self) -> Result<()>{
        self.set_readiness.set_readiness(Ready::readable()).map_err(Error::Io)
    }
}

impl Evented for Signal {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        self.registration.register(poll, token, interest,opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        self.registration.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        poll.deregister(&self.registration)
    }
}

impl<'a, T: Read + Write + Async + Send> Handle<'a, T>
    where <T as Async>::Ev: Send
{
    const DATA: Token = Token(0);
    const STOP: Token = Token(1);

    /// Returns a `Signal` which can be used to interrupt a pending `wait_interruptible`.
    pub fn get_interrupt(&mut self) -> Result<Signal> {
        let signal = Signal::new();
        self.poll.register(&signal, Self::STOP, Ready::readable(), PollOpt::edge() | PollOpt::oneshot())?;
        Ok(signal)
    }

    /// Returns a pair of functions which can be used to wait and to stop that wait.
    pub fn wait_interruptible(mut self) -> Result<()>
    {
        let ev = {
            let stream = self.session.stream.get_ref();
            stream.set_nonblocking(true)?;
            let ev = stream.get_evented();
            self.poll.register(&ev, Self::DATA, Ready::readable(), PollOpt::edge() | PollOpt::oneshot())?;
            ev
        };

        let mut events = Events::with_capacity(2);

        'wait: loop {
            self.poll.poll(&mut events, Some(self.keepalive))?;
            if events.is_empty() {
                // Timeout: we need to refresh the IDLE connection
                self.terminate()?;
                self.init()?;
            } else {
                for event in events.iter() {
                    if event.token() == Self::STOP { break 'wait; }
                    let mut v = Vec::new();
                    match self.session.readline(&mut v) {
                        Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {},
                        Err(e) => return Err(e),
                        Ok(_) => break 'wait,
                    }
                    self.poll.reregister(&ev, Self::DATA, Ready::readable(), PollOpt::edge() | PollOpt::oneshot())?;
                }
            }
        }

        self.session.stream.get_ref().set_nonblocking(false)?;
        Ok(())
    }
}

impl<'a, T: Read + Write> Drop for Handle<'a, T> {
    fn drop(&mut self) {
        // we don't want to panic here if we can't terminate the Idle
        let _ = self.terminate().is_ok();
    }
}

impl SetReadTimeout for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        TcpStream::set_read_timeout(self, timeout).map_err(Error::Io)
    }
}

impl SetReadTimeout for TlsStream<TcpStream> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.get_ref().set_read_timeout(timeout).map_err(Error::Io)
    }
}

/// A copy of `mio::unix::EventedFd` which stores the `RawFd` instead of referencing it.
pub struct EventedFd(RawFd);

impl Evented for EventedFd {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()>
    {
        unix::EventedFd(&self.0).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()>
    {
        unix::EventedFd(&self.0).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        unix::EventedFd(&self.0).deregister(poll)
    }
}

impl Async for TcpStream {
    type Ev = EventedFd;

    fn get_evented(&self) -> Self::Ev { EventedFd(self.as_raw_fd()) }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        TcpStream::set_nonblocking(self, nonblocking).map_err(Error::Io)
    }
}

impl<S: Read + Write + Async> Async for TlsStream<S> {
    type Ev = S::Ev;

    fn get_evented(&self) -> Self::Ev { self.get_ref().get_evented() }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
}

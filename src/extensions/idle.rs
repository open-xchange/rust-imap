//! Adds support for the IMAP IDLE command specificed in [RFC
//! 2177](https://tools.ietf.org/html/rfc2177).

use client::Session;
use error::{Error, Result};
use native_tls::TlsStream;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use mio::{Events, Interests, Poll, Token};
use mio::unix::SourceFd;
pub use mio::Waker;

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
pub struct Handle<'a, T: Read + Write + 'a> {
    session: &'a mut Session<T>,
    keepalive: Duration,
    done: bool,
    poll: Poll,
    waker: Arc<Mutex<Waker>>,
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
    /// Returns a `RawFd` for the stream.
    fn get_fd(&self) -> RawFd;

    /// Set the transport to be blocking (the default, or when `nonblocking` is
    /// `false`) or nonblocking (when `nonblocking` is `true`).
    ///
    /// See also `std::net::TcpStream::set_nonblocking`.
    fn set_nonblocking(&self, nonblocking: bool) -> Result<()>;
}

impl<'a, T: Read + Write + 'a> Handle<'a, T> {

    const DATA: Token = Token(0);
    const STOP: Token = Token(1);

    pub(crate) fn make(session: &'a mut Session<T>) -> Result<Self> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), Self::STOP)?;
        let mut h = Handle {
            session,
            keepalive: Duration::from_secs(29 * 60),
            done: false,
            poll,
            waker: Arc::new(Mutex::new(waker)),
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

impl<'a, T: SetReadTimeout + Read + Write + 'a> Handle<'a, T> {
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

impl<'a, T: Read + Write + Async + 'a> Handle<'a, T> {

    /// Returns a `Waker` which can be used to interrupt a pending `wait_interruptible`.
    pub fn get_interrupt(&mut self) -> Arc<Mutex<Waker>> { self.waker.clone() }

    /// Block until the selected mailbox changes.
    ///
    /// The function also returns when the previously configured timeout expires
    /// or the `Waker` returned by a previous call to `get_interrupt` is used.
    pub fn wait_interruptible(mut self) -> Result<()>
    {
        let stream = self.session.stream.get_ref();
        self.poll.registry().register(&SourceFd(&stream.get_fd()), Self::DATA, Interests::READABLE)?;

        let mut events = Events::with_capacity(2);

        loop {
            self.poll.poll(&mut events, Some(self.keepalive))?;
            if events.is_empty() {
                // Timeout: we need to refresh the IDLE connection
                self.terminate()?;
                self.init()?;
            } else {
                for event in events.iter() {
                    if event.token() == Self::STOP { return Ok(()); }
                    self.session.stream.get_ref().set_nonblocking(true)?;
                    let mut v = Vec::new();
                    let res = self.session.readline(&mut v);
                    let cleanup_res = self.session.stream.get_ref().set_nonblocking(false);
                    match res {
                        Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {},
                        Err(e) => return Err(e),
                        Ok(_) => return cleanup_res,
                    }
                }
            }
        }
    }
}

impl<'a, T: Read + Write + 'a> Drop for Handle<'a, T> {
    fn drop(&mut self) {
        // we don't want to panic here if we can't terminate the Idle
        let _ = self.terminate().is_ok();
    }
}

impl<'a> SetReadTimeout for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        TcpStream::set_read_timeout(self, timeout).map_err(Error::Io)
    }
}

impl<'a> SetReadTimeout for TlsStream<TcpStream> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.get_ref().set_read_timeout(timeout).map_err(Error::Io)
    }
}

impl Async for TcpStream {
    fn get_fd(&self) -> RawFd { self.as_raw_fd() }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        TcpStream::set_nonblocking(self, nonblocking).map_err(Error::Io)
    }
}

impl<S: Read + Write + Async> Async for TlsStream<S> {
    fn get_fd(&self) -> RawFd { self.get_ref().get_fd() }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
}

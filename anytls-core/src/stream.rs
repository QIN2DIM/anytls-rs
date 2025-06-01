use crate::frame::{Frame, CMD_PSH, CMD_FIN};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::{Arc, Mutex};
use bytes::Bytes;

#[derive(Debug)]
pub struct Stream {
    pub id: u32,
    
    // For reading data from the session
    rx: mpsc::Receiver<Bytes>,
    
    // For writing frames to the session
    frame_tx: mpsc::Sender<Frame>,
    
    // Buffer for partial reads
    read_buffer: Option<Bytes>,
    read_offset: usize,
    
    // Stream state
    closed: Arc<Mutex<bool>>,
    
    // For notifying when stream is closed
    close_tx: Option<oneshot::Sender<()>>,
}

impl Stream {
    pub fn new(
        id: u32,
        rx: mpsc::Receiver<Bytes>,
        frame_tx: mpsc::Sender<Frame>,
        close_tx: oneshot::Sender<()>,
    ) -> Self {
        Self {
            id,
            rx,
            frame_tx,
            read_buffer: None,
            read_offset: 0,
            closed: Arc::new(Mutex::new(false)),
            close_tx: Some(close_tx),
        }
    }
    
    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }
    
    fn mark_closed(&mut self) {
        *self.closed.lock().unwrap() = true;
        if let Some(tx) = self.close_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.is_closed() {
            return Poll::Ready(Ok(()));
        }
        
        // First, try to read from the existing buffer
        if let Some(data) = &self.read_buffer {
            let remaining = data.len() - self.read_offset;
            let to_copy = remaining.min(buf.remaining());
            
            buf.put_slice(&data[self.read_offset..self.read_offset + to_copy]);
            
            let new_offset = self.read_offset + to_copy;
            if new_offset >= data.len() {
                self.read_buffer = None;
                self.read_offset = 0;
            } else {
                self.read_offset = new_offset;
            }
            
            return Poll::Ready(Ok(()));
        }
        
        // Try to receive new data
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                
                if to_copy < data.len() {
                    self.read_buffer = Some(data);
                    self.read_offset = to_copy;
                }
                
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.mark_closed();
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is closed",
            )));
        }
        
        let frame = Frame::with_data(CMD_PSH, self.id, buf.to_vec());
        
        match self.frame_tx.try_send(frame) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, register for wakeup
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session is closed",
                )))
            }
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.is_closed() {
            return Poll::Ready(Ok(()));
        }
        
        let frame = Frame::new(CMD_FIN, self.id);
        
        match self.frame_tx.try_send(frame) {
            Ok(()) => {
                self.mark_closed();
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.mark_closed();
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.is_closed() {
            let frame = Frame::new(CMD_FIN, self.id);
            let _ = self.frame_tx.try_send(frame);
            self.mark_closed();
        }
    }
} 
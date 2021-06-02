use std::sync::Arc;
use tokio::sync::Mutex;

use tokio::net::{UnixListener, UnixStream};

use crate::error::HandleResult;
use crate::handler::SSHAgentHandler;
use crate::protocol::Request;

pub struct Agent;

impl Agent {
    async fn handle_client<T: SSHAgentHandler>(
        handler: Arc<Mutex<T>>,
        mut stream: UnixStream,
    ) -> HandleResult<()> {
        debug!("handling new connection");
        loop {
            let req = Request::read(&mut stream).await?;
            debug!("request: {:?}", req);

            let response = handler.lock().await.handle_request(req).await?;

            debug!("handler: {:?}", response);
            response.write(&mut stream).await?;
        }
    }

    pub async fn run<T: SSHAgentHandler + 'static>(handler: T, listener: UnixListener) {
        let arc_handler = Arc::new(Mutex::new(handler));

        // accept the connections and spawn a new task for each one
        while let Some((stream, _)) = listener.accept().await.ok() {
            match Agent::handle_client(arc_handler.clone(), stream).await {
                Ok(_) => {}
                Err(e) => debug!("handler: {:?}", e),
            };
        }
    }
}

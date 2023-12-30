use shroom_proxy::app::{AppConfig, App};
use config::Config;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    let settings: AppConfig = Config::builder()
        .add_source(config::File::with_name("config"))
        .build()
        .unwrap()
        .try_deserialize()?;


    let mut app = App::new(settings);
    app.run().await
}

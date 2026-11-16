pub mod atomic;
pub mod init_wizard;
pub mod run_pipeline;

use clap::ValueEnum;

#[derive(Clone, Debug, ValueEnum)]
pub enum ModeArg {
    Red,
    Blue,
    Purple,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum BackendArg {
    Docker,
    Gvisor,
    Firecracker,
    Host,
}

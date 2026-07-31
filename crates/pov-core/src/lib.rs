//! Core identity, repository, and storage boundary contracts for POV Story.

#![forbid(unsafe_code)]

pub mod auth;
pub mod conversation;
#[cfg(unix)]
pub mod generation_worker;
pub mod identity;
pub mod job;
#[cfg(unix)]
pub mod loopback_llm;
pub mod postgres;
pub mod process;
pub mod provider;
pub mod repository;
pub mod storage;

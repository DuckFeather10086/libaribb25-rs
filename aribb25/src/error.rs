use thiserror::Error;

#[derive(Debug, Error)]
pub enum B25Error {
    #[error("invalid parameter")]
    InvalidParam,
    #[error("not enough memory")]
    NoEnoughMemory,
    #[error("non-TS input stream")]
    NonTsInputStream,
    #[error("no PAT found in first 16MB")]
    NoPat,
    #[error("no PMT found in first 32MB")]
    NoPmt,
    #[error("no ECM found in first 32MB")]
    NoEcm,
    #[error("B-CAS card not set")]
    EmptyBCasCard,
    #[error("invalid B-CAS card status")]
    InvalidBCasStatus,
    #[error("ECM processing failure")]
    EcmProcFailure,
    #[error("decryption failure")]
    DecryptFailure,
    #[error("PAT parse failure")]
    PatParseFailure,
    #[error("PMT parse failure")]
    PmtParseFailure,
    #[error("ECM parse failure")]
    EcmParseFailure,
    #[error("CAT parse failure")]
    CatParseFailure,
    #[error("EMM parse failure")]
    EmmParseFailure,
    #[error("EMM processing failure")]
    EmmProcFailure,
    #[error("B-CAS card error: {0}")]
    BCasCard(#[from] BCasCardError),
}

#[derive(Debug, Error)]
pub enum BCasCardError {
    #[error("invalid parameter")]
    InvalidParameter,
    #[error("not initialized")]
    NotInitialized,
    #[error("no smart card reader found")]
    NoSmartCardReader,
    #[error("all reader connection attempts failed")]
    AllReadersConnectionFailed,
    #[error("not enough memory")]
    NoEnoughMemory,
    #[error("transmit failed")]
    TransmitFailed,
    #[error("PC/SC error: {0}")]
    PcSc(#[from] pcsc::Error),
}

#[derive(Debug, Error)]
pub enum Multi2Error {
    #[error("invalid parameter")]
    InvalidParameter,
    #[error("CBC init not set")]
    UnsetCbcInit,
    #[error("system key not set")]
    UnsetSystemKey,
    #[error("scramble key not set")]
    UnsetScrambleKey,
}

/// Warnings returned as Ok() values (non-fatal)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B25Warn {
    UnpurchasedEcm,
    TsSectionIdMismatch,
    BrokenTsSection,
    PatNotComplete,
    PmtNotComplete,
    EcmNotComplete,
}

pub type B25Result<T> = Result<T, B25Error>;
pub type BCasResult<T> = Result<T, BCasCardError>;
pub type Multi2Result<T> = Result<T, Multi2Error>;

use spectra::spectra_metric;

spectra_metric! {
    LeptonBot {
        store: "lepton",
        name: "lepton_bot",
        version: "0.1.0",
        description: "Bot account lifecycle ops. Labels: operation, outcome, error_class.",
    }
}

use spectra::spectra_metric;

spectra_metric! {
    LeptonServiceUser {
        store: "lepton",
        name: "lepton_service_user",
        version: "0.1.0",
        description: "Service user lifecycle ops. Labels: operation, outcome, error_class.",
    }
}

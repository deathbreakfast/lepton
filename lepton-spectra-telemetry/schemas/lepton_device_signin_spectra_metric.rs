use spectra::spectra_metric;

spectra_metric! {
    LeptonDeviceSignin {
        store: "lepton",
        name: "lepton_device_signin",
        version: "0.1.0",
        description: "Device sign-in ops (RFC 8628). Labels: operation, outcome, error_class.",
    }
}

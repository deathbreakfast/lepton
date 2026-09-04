use leptos::prelude::*;
use orbital_base_components::OpenBind;
use orbital_motion::{MotionCurve, OrbitalPresence, PresenceMotion};
use orbital_core_components::{
    Dialog, DialogBody, DialogContent, DialogDismissConfig, DialogSurface, DialogTitle, Material,
    MaterialCorners, MaterialElevation, MaterialVariant,
};

/// Shared glass modal frame for auth, password-reset, and step-up dialogs.
#[component]
pub fn AuthModalShell(
    open: OpenBind,
    title: Signal<String>,
    /// Backdrop / Escape dismiss. Step-up passes locked dismiss.
    #[prop(optional)]
    dismiss: Option<DialogDismissConfig>,
    children: Children,
) -> impl IntoView {
    let open_signal = open.signal();
    let panel_motion =
        Signal::from(PresenceMotion::fade_scale().with_curve(MotionCurve::DecelerateMid));
    let dismiss = dismiss.unwrap_or_default();

    // DialogSurface ships a solid canvas panel (bg, border, padding, xl radius).
    // Material(Frost, Modal) is the single visible surface — not nested inside an opaque shell.
    // Fixed width so sign-in, sign-up, logout, and reset share one frame (not fit-content).
    let (style_sheet, class_names) = turf::inline_style_sheet_values! {
        .DialogFrame {
            background: transparent;
            border: none;
            padding: 0;
            width: min(400px, calc(100vw - 48px));
            box-sizing: border-box;
        }

        .DialogMaterial {
            border-radius: var(--orb-radius-xl);
            padding: 24px;
            box-sizing: border-box;
            width: 100%;
        }
    };

    view! {
        <style>{style_sheet}</style>
        <Dialog open=open dismiss=dismiss>
            <OrbitalPresence
                appear=true
                show=open_signal
                motion=panel_motion
                respect_reduced_motion=true
            >
                <DialogSurface class=class_names.dialog_frame>
                    <Material
                        class=class_names.dialog_material
                        variant=MaterialVariant::Frost
                        elevation=MaterialElevation::Modal
                        corners=MaterialCorners::Rounded
                    >
                        <DialogBody>
                            <DialogTitle>{move || title.get()}</DialogTitle>
                            <DialogContent>{children()}</DialogContent>
                        </DialogBody>
                    </Material>
                </DialogSurface>
            </OrbitalPresence>
        </Dialog>
    }
}

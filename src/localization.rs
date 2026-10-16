//! Native multi-language matrix. Localized strings live as static byte
//! data keyed by enum — no heap, no formatter, no layout wrappers on the
//! hot path. The RTL flag drives bidirectional rendering overrides.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SupportedLanguage {
    English = 0,
    Spanish = 1,
    French = 2,
    Portuguese = 3,
    German = 4,
    Italian = 5,
    Arabic = 6,
}

pub struct LocalizationDescriptor {
    pub text_payload: &'static str,
    pub is_right_to_left: bool,
}

impl SupportedLanguage {
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::English),
            1 => Some(Self::Spanish),
            2 => Some(Self::French),
            3 => Some(Self::Portuguese),
            4 => Some(Self::German),
            5 => Some(Self::Italian),
            6 => Some(Self::Arabic),
            _ => None,
        }
    }

    /// Localized prominent-disclosure warning, fetched without allocation.
    pub fn fetch_disclosure_string(self) -> LocalizationDescriptor {
        match self {
            Self::English => LocalizationDescriptor {
                text_payload: "Threat Alert: Multi-agent core has isolated a zero-day modification vector inside localized memory boundaries.",
                is_right_to_left: false,
            },
            Self::Spanish => LocalizationDescriptor {
                text_payload: "Alerta de Amenaza: El núcleo multiagente ha aislado un vector de modificación de día cero dentro de la memoria local.",
                is_right_to_left: false,
            },
            Self::French => LocalizationDescriptor {
                text_payload: "Alerte de Menace : Le noyau multi-agent a isolé un vecteur de modification zero-day dans les limites de la mémoire locale.",
                is_right_to_left: false,
            },
            Self::Portuguese => LocalizationDescriptor {
                text_payload: "Alerta de Ameaça: O núcleo multiagente isolou um vetor de modificação zero-day dentro dos limites da memória local.",
                is_right_to_left: false,
            },
            Self::German => LocalizationDescriptor {
                text_payload: "Bedrohungswarnung: Der Multi-Agenten-Kern hat einen Zero-Day-Modifikationsvektor innerhalb lokaler Speichergrenzen isoliert.",
                is_right_to_left: false,
            },
            Self::Italian => LocalizationDescriptor {
                text_payload: "Avviso di Minaccia: Il nucleo multi-agente ha isolato un vettore di modifica zero-day all'interno dei confini della memoria locale.",
                is_right_to_left: false,
            },
            Self::Arabic => LocalizationDescriptor {
                text_payload: "تحذير أمني: قامت نواة الوكيل المتعدد بعزل موجّه تعديل يوم الصفر داخل حدود الذاكرة المحلية المحمية.",
                is_right_to_left: true,
            },
        }
    }
}

/// FFI: returns a pointer to the NUL-free UTF-8 payload and its length.
/// The payload is `'static`, so the host must NOT free it.
#[no_mangle]
pub unsafe extern "C" fn swarm_localized_disclosure(
    lang_code: u8,
    out_len: *mut usize,
    out_rtl: *mut u8,
) -> *const u8 {
    let lang = match SupportedLanguage::from_code(lang_code) {
        Some(l) => l,
        None => SupportedLanguage::English,
    };
    let d = lang.fetch_disclosure_string();
    if !out_len.is_null() {
        *out_len = d.text_payload.len();
    }
    if !out_rtl.is_null() {
        *out_rtl = d.is_right_to_left as u8;
    }
    d.text_payload.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_languages_resolve() {
        for code in 0..7u8 {
            let lang = SupportedLanguage::from_code(code).expect("code must map");
            let d = lang.fetch_disclosure_string();
            assert!(!d.text_payload.is_empty());
        }
        assert!(SupportedLanguage::from_code(7).is_none());
    }

    #[test]
    fn arabic_is_rtl_only() {
        for code in 0..7u8 {
            let d = SupportedLanguage::from_code(code).unwrap().fetch_disclosure_string();
            assert_eq!(d.is_right_to_left, code == 6, "code {}", code);
        }
    }

    #[test]
    fn ffi_returns_static_payload() {
        let mut len = 0usize;
        let mut rtl = 0u8;
        let ptr = unsafe { swarm_localized_disclosure(6, &mut len, &mut rtl) };
        assert!(!ptr.is_null() && len > 0 && rtl == 1);
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        assert!(core::str::from_utf8(bytes).is_ok());
    }
}

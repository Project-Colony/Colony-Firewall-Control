//! Embedded fallback icon: a burgundy shield on a parchment disc,
//! generated in code so the tray still has an icon when the
//! "colony-firewall" theme icon is not installed (e.g. running from a
//! build tree).
//!
//! The generator is pure pixel math - no image crate, no assets - and
//! returns plain buffers so it can be unit tested without ksni.

/// The raster sizes handed to the StatusNotifierItem host. 22 px is the
/// common tray size, 48 px covers HiDPI hosts that pick the largest.
pub const SIZES: [usize; 2] = [22, 48];

/// Deep burgundy, the shield.
const BURGUNDY: [u8; 3] = [0x7c, 0x1f, 0x2e];
/// Darker burgundy, the disc rim.
const RIM: [u8; 3] = [0x55, 0x15, 0x1f];
/// Warm parchment, the disc.
const PARCHMENT: [u8; 3] = [0xf2, 0xe8, 0xd5];

/// One ARGB32 raster (network byte order: A, R, G, B per pixel), the
/// format the StatusNotifierItem spec wants for `IconPixmap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pixmap {
    pub width: usize,
    pub height: usize,
    pub argb: Vec<u8>,
}

/// True when the normalized point (u, v) in [0, 1]^2 is inside the
/// shield: straight sides down to v = 0.55, then a taper to a point.
fn in_shield(u: f32, v: f32) -> bool {
    const TOP: f32 = 0.24;
    const WAIST: f32 = 0.55;
    const TIP: f32 = 0.80;
    const HALF_W: f32 = 0.20;
    let dx = (u - 0.5).abs();
    if !(TOP..=TIP).contains(&v) {
        false
    } else if v <= WAIST {
        dx <= HALF_W
    } else {
        dx <= HALF_W * (TIP - v) / (TIP - WAIST)
    }
}

/// Renders the shield-on-disc at `size` x `size`.
pub fn shield_pixmap(size: usize) -> Pixmap {
    debug_assert!(size >= 8, "an icon smaller than 8px is just noise");
    let mut argb = Vec::with_capacity(size * size * 4);
    let last = (size - 1) as f32;
    let center = last / 2.0;
    let radius = size as f32 / 2.0 - 0.5;
    let rim_width = (size as f32 / 16.0).max(1.0);

    for y in 0..size {
        for x in 0..size {
            let (dx, dy) = (x as f32 - center, y as f32 - center);
            let r = (dx * dx + dy * dy).sqrt();
            let (a, rgb) = if r > radius {
                (0x00, [0, 0, 0])
            } else if r > radius - rim_width {
                (0xff, RIM)
            } else if in_shield(x as f32 / last, y as f32 / last) {
                (0xff, BURGUNDY)
            } else {
                (0xff, PARCHMENT)
            };
            argb.extend_from_slice(&[a, rgb[0], rgb[1], rgb[2]]);
        }
    }
    Pixmap {
        width: size,
        height: size,
        argb,
    }
}

/// All embedded rasters, smallest first.
pub fn all() -> Vec<Pixmap> {
    SIZES.iter().map(|&s| shield_pixmap(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ARGB pixel at (x, y).
    fn px(p: &Pixmap, x: usize, y: usize) -> [u8; 4] {
        let i = (y * p.width + x) * 4;
        [p.argb[i], p.argb[i + 1], p.argb[i + 2], p.argb[i + 3]]
    }

    #[test]
    fn dimensions_and_length_hold_for_every_size() {
        for &size in &SIZES {
            let p = shield_pixmap(size);
            assert_eq!(p.width, size);
            assert_eq!(p.height, size);
            assert_eq!(p.argb.len(), size * size * 4);
            assert!(!p.argb.is_empty());
        }
    }

    #[test]
    fn corners_are_transparent_and_disc_is_opaque() {
        for &size in &SIZES {
            let p = shield_pixmap(size);
            // The disc is inscribed in the square; corners lie outside it.
            assert_eq!(px(&p, 0, 0)[0], 0x00, "top-left corner must be transparent");
            assert_eq!(
                px(&p, size - 1, size - 1)[0],
                0x00,
                "bottom-right corner must be transparent"
            );
            // Dead center is inside the shield, fully opaque.
            assert_eq!(px(&p, size / 2, size / 2)[0], 0xff);
        }
    }

    #[test]
    fn shield_disc_and_rim_colors_all_appear() {
        for &size in &SIZES {
            let p = shield_pixmap(size);
            let has = |rgb: [u8; 3]| {
                p.argb
                    .chunks_exact(4)
                    .any(|c| c[0] == 0xff && [c[1], c[2], c[3]] == rgb)
            };
            assert!(has(BURGUNDY), "{size}px: no burgundy shield pixel");
            assert!(has(PARCHMENT), "{size}px: no parchment disc pixel");
            assert!(has(RIM), "{size}px: no rim pixel");
        }
    }

    #[test]
    fn center_is_burgundy_on_parchment() {
        for &size in &SIZES {
            let p = shield_pixmap(size);
            let center = px(&p, size / 2, size / 2);
            assert_eq!([center[1], center[2], center[3]], BURGUNDY);
            // Just inside the rim on the horizontal midline is parchment
            // (left of the shield).
            let edge_x = (size as f32 / 8.0).ceil() as usize + 1;
            let side = px(&p, edge_x, size / 2);
            assert_eq!(
                [side[1], side[2], side[3]],
                PARCHMENT,
                "{size}px: expected parchment beside the shield"
            );
        }
    }

    #[test]
    fn alpha_channel_is_really_used() {
        // Both fully transparent and fully opaque pixels must exist,
        // otherwise the "ARGB" is a lie.
        for p in all() {
            let alphas: Vec<u8> = p.argb.chunks_exact(4).map(|c| c[0]).collect();
            assert!(alphas.contains(&0x00));
            assert!(alphas.contains(&0xff));
        }
    }

    #[test]
    fn all_returns_every_advertised_size() {
        let rasters = all();
        assert_eq!(rasters.len(), SIZES.len());
        for (p, &s) in rasters.iter().zip(SIZES.iter()) {
            assert_eq!((p.width, p.height), (s, s));
        }
    }
}

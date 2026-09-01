use image::{
    DynamicImage, GenericImageView, ImageDecoder, ImageError, ImageFormat, ImageReader, Limits,
    Rgb, RgbImage, codecs::jpeg::JpegEncoder,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    io::{self, Cursor, Write},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_SOURCE_BYTES: usize = 10 * 1_024 * 1_024;
const MAX_OUTPUT_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_SOURCE_DIMENSION: u32 = 4_096;
const MAX_PIXELS: u64 = 4_000_000;
const MAX_DECODED_BYTES: u64 = 32 * 1_024 * 1_024;
const OUTPUT_DIMENSION: u32 = 1_600;
const JPEG_QUALITY: u8 = 85;
pub(crate) const SANITIZER_VERSION: &str = "image-rs-jpeg-v1";

#[derive(Debug, Error)]
pub(crate) enum PhotoError {
    #[error("profile photo source is too large")]
    SourceTooLarge,
    #[error("profile photo format is not supported")]
    UnsupportedFormat,
    #[error("profile photo dimensions are not allowed")]
    InvalidDimensions,
    #[error("profile photo could not be decoded")]
    InvalidImage,
    #[error("sanitized profile photo is too large")]
    OutputTooLarge,
}

/// Metadata-free JPEG bytes suitable for encryption and private persistence.
pub(crate) struct SanitizedPhoto {
    pub(crate) bytes: Zeroizing<Vec<u8>>,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) sha256: [u8; 32],
}

impl fmt::Debug for SanitizedPhoto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedPhoto")
            .field(
                "bytes",
                &format_args!("[REDACTED; {} bytes]", self.bytes.len()),
            )
            .field("width", &self.width)
            .field("height", &self.height)
            .field("sha256", &"[REDACTED]")
            .finish()
    }
}

pub(crate) fn sanitize_profile_photo(source: &[u8]) -> Result<SanitizedPhoto, PhotoError> {
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err(PhotoError::SourceTooLarge);
    }
    let format = image::guess_format(source).map_err(|_| PhotoError::UnsupportedFormat)?;
    if !matches!(format, ImageFormat::Jpeg | ImageFormat::Png) {
        return Err(PhotoError::UnsupportedFormat);
    }

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_DIMENSION);
    limits.max_image_height = Some(MAX_SOURCE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODED_BYTES);
    let mut reader = ImageReader::with_format(Cursor::new(source), format);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(map_decode_error)?;
    let dimensions = decoder.dimensions();
    validate_dimensions(dimensions)?;
    if decoder.total_bytes() > MAX_DECODED_BYTES {
        return Err(PhotoError::InvalidDimensions);
    }
    let orientation = decoder
        .orientation()
        .map_err(|_| PhotoError::InvalidImage)?;
    let mut decoded = DynamicImage::from_decoder(decoder).map_err(|_| PhotoError::InvalidImage)?;
    decoded.apply_orientation(orientation);
    let mut sanitized = resize(composite_on_white(decoded));
    let (width, height) = sanitized.dimensions();
    let mut writer = BoundedWriter::new(MAX_OUTPUT_BYTES);
    let encoded = JpegEncoder::new_with_quality(&mut writer, JPEG_QUALITY).encode_image(&sanitized);
    zeroize_pixels(&mut sanitized);
    if writer.exceeded {
        return Err(PhotoError::OutputTooLarge);
    }
    encoded.map_err(|_| PhotoError::InvalidImage)?;
    let output = Zeroizing::new(writer.bytes);
    let sha256 = Sha256::digest(&*output).into();
    Ok(SanitizedPhoto {
        bytes: output,
        width,
        height,
        sha256,
    })
}

fn map_decode_error(error: ImageError) -> PhotoError {
    if matches!(error, ImageError::Limits(_)) {
        PhotoError::InvalidDimensions
    } else {
        PhotoError::InvalidImage
    }
}

fn composite_on_white(image: DynamicImage) -> DynamicImage {
    let mut rgba = image.into_rgba8();
    let (width, height) = rgba.dimensions();
    let rgb = RgbImage::from_fn(width, height, |x, y| {
        let pixel = rgba.get_pixel(x, y).0;
        let alpha = u16::from(pixel[3]);
        let blend = |channel: u8| {
            u8::try_from((u16::from(channel) * alpha + 255 * (255 - alpha) + 127) / 255)
                .unwrap_or(255)
        };
        Rgb([blend(pixel[0]), blend(pixel[1]), blend(pixel[2])])
    });
    rgba.as_mut().zeroize();
    DynamicImage::ImageRgb8(rgb)
}

fn validate_dimensions((width, height): (u32, u32)) -> Result<(), PhotoError> {
    let pixels = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || width > MAX_SOURCE_DIMENSION
        || height > MAX_SOURCE_DIMENSION
        || pixels > MAX_PIXELS
    {
        return Err(PhotoError::InvalidDimensions);
    }
    Ok(())
}

fn resize(mut image: DynamicImage) -> DynamicImage {
    let (width, height) = image.dimensions();
    if width <= OUTPUT_DIMENSION && height <= OUTPUT_DIMENSION {
        image
    } else {
        let resized = image.thumbnail(OUTPUT_DIMENSION, OUTPUT_DIMENSION);
        zeroize_pixels(&mut image);
        resized
    }
}

fn zeroize_pixels(image: &mut DynamicImage) {
    if let Some(rgb) = image.as_mut_rgb8() {
        rgb.as_mut().zeroize();
    } else if let Some(rgba) = image.as_mut_rgba8() {
        rgba.as_mut().zeroize();
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(256 * 1_024)),
            maximum,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(buffer.len())
            .is_none_or(|length| length > self.maximum)
        {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "sanitized image exceeds limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedWriter, PhotoError, SANITIZER_VERSION, sanitize_profile_photo};
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::{Cursor, Write};

    fn jpeg_with_exif_marker() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut jpeg = Vec::new();
        DynamicImage::ImageRgb8(RgbImage::from_pixel(8, 6, image::Rgb([20, 40, 60])))
            .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)?;
        let marker = b"Exif\0\0GPS-secret-marker";
        let length = u16::try_from(marker.len() + 2)?;
        let mut with_metadata = Vec::with_capacity(jpeg.len() + marker.len() + 4);
        with_metadata.extend_from_slice(&jpeg[..2]);
        with_metadata.extend_from_slice(&[0xff, 0xe1]);
        with_metadata.extend_from_slice(&length.to_be_bytes());
        with_metadata.extend_from_slice(marker);
        with_metadata.extend_from_slice(&jpeg[2..]);
        Ok(with_metadata)
    }

    #[test]
    fn reencodes_without_embedded_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let source = jpeg_with_exif_marker()?;
        let sanitized = sanitize_profile_photo(&source)?;
        assert_eq!((sanitized.width, sanitized.height), (8, 6));
        assert!(sanitized.bytes.starts_with(&[0xff, 0xd8]));
        assert!(
            !sanitized
                .bytes
                .windows(b"GPS-secret-marker".len())
                .any(|window| window == b"GPS-secret-marker")
        );
        assert_eq!(SANITIZER_VERSION, "image-rs-jpeg-v1");
        Ok(())
    }

    #[test]
    fn rejects_non_images_and_excessive_dimensions() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            sanitize_profile_photo(b"not an image"),
            Err(PhotoError::UnsupportedFormat)
        ));

        let mut oversized = Vec::new();
        DynamicImage::ImageRgb8(RgbImage::new(4_097, 1))
            .write_to(&mut Cursor::new(&mut oversized), ImageFormat::Png)?;
        assert!(matches!(
            sanitize_profile_photo(&oversized),
            Err(PhotoError::InvalidDimensions)
        ));
        Ok(())
    }

    #[test]
    fn composites_transparency_before_jpeg_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let mut source = Vec::new();
        let mut rgba = image::RgbaImage::from_pixel(2, 2, image::Rgba([0, 0, 0, 0]));
        rgba.put_pixel(1, 0, image::Rgba([0, 0, 0, 127]));
        rgba.put_pixel(0, 1, image::Rgba([0, 0, 0, 255]));
        DynamicImage::ImageRgba8(rgba).write_to(&mut Cursor::new(&mut source), ImageFormat::Png)?;
        let sanitized = sanitize_profile_photo(&source)?;
        let rgb = image::load_from_memory(&sanitized.bytes)?.to_rgb8();
        assert!(rgb.get_pixel(0, 0).0.iter().all(|channel| *channel > 235));
        assert!(
            rgb.get_pixel(1, 0)
                .0
                .iter()
                .all(|channel| (100..=155).contains(channel))
        );
        assert!(rgb.get_pixel(0, 1).0.iter().all(|channel| *channel < 20));
        Ok(())
    }

    #[test]
    fn resizes_and_bounds_output_writes() -> Result<(), Box<dyn std::error::Error>> {
        let mut source = Vec::new();
        DynamicImage::ImageRgb8(RgbImage::from_pixel(2_000, 1_000, image::Rgb([10, 20, 30])))
            .write_to(&mut Cursor::new(&mut source), ImageFormat::Png)?;
        let sanitized = sanitize_profile_photo(&source)?;
        assert_eq!((sanitized.width, sanitized.height), (1_600, 800));

        let mut writer = BoundedWriter::new(3);
        writer.write_all(&[1, 2, 3])?;
        assert!(writer.write_all(&[4]).is_err());
        assert!(writer.exceeded);
        Ok(())
    }
}

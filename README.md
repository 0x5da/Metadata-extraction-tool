## Artifact Extractor
*Created by 0x5da (toasty/OsintToast/WoahToast)*

Metadata extraction tool for documents, images, and archives. Recovers EXIF data from photographs, embedded metadata from PDFs and Office documents, ZIP archives structure, and binary file information. Useful for OSINT, forensics, and data discovery investigations.

### Why I Built This

Developed for OSINT researchers and digital forensics professionals who need to extract intelligence from files and metadata. Built to rapidly recover embedded information (EXIF GPS coordinates, document authors, creation timestamps, archive structures)—enabling attribution analysis, timeline reconstruction, and discovery of sensitive information users may have accidentally disclosed through document metadata.

### What It Does

- **EXIF Extraction**: Image GPS coordinates, camera model, timestamps, lens info
- **PDF Metadata**: Title, author, creation date, producer, embedded XMP data
- **ZIP Analysis**: File list, compression method, internal structure, hidden files
- **Document Extraction**: Office (DOCX/XLSX/PPTX) metadata via ZIP parsing
- **Image Metadata**: PNG IHDR inspection, BMP headers, TIFF tags
- **Archive Recursion**: Nested ZIP/GZIP analysis, multiple file level support

### How It Works

Tool detects file type via MIME type and extension, then routes to appropriate extraction handler. Binary format parsing uses Python's `struct` module for endianness-aware header reading. EXIF tags are decoded from binary IFD (Image File Directory) structures. Office documents are handled as ZIP files with XML metadata. PDF metadata extracted via text parsing (simplified; fully-encrypted PDFs skipped). Recursive archive handling re-extracts nested compressed files.

### Installation & Usage

```bash
pip install -r requirements.txt
python extractor.py [file/directory] [-o OUTPUT] [-r RECURSIVE]
```

**Arguments:**
- `file/directory`: Single file or directory to process
- `-o, --output`: Export results to JSON file
- `-r, --recursive`: Process subdirectories (default: no)

**Examples:**
```bash
# Extract metadata from single image
python extractor.py photo.jpg

# Process entire directory
python extractor.py ./documents -r

# Export all metadata to JSON
python extractor.py ./images -o metadata_report.json -r

# Specific file type
python extractor.py data.zip
```

### Supported Formats

| Format | Extraction | Details |
|--------|-----------|---------|
| JPEG | EXIF, thumbnail | Camera, GPS, timestamps |
| PNG | IHDR chunk | Dimensions, color type, creation time |
| TIFF | Full EXIF tags | Professional camera data |
| PDF | XMP, Info dict | Author, title, creation date |
| DOCX/XLSX/PPTX | core.xml properties | Office metadata (via ZIP) |
| ZIP | File list, structure | Compression, sizes, paths |
| GZIP | Header, timestamps | Archived filename, timestamp |
| BMP | Header info | Dimensions, color depth |

### Output Example (Image)

```
======================================================================
METADATA EXTRACTION REPORT
======================================================================

File: vacation_photo.jpg
Size: 2345678 bytes
Type: JPEG Image

[EXIF Data]
===================================
Camera: Canon EOS 5D Mark IV
Lens: Canon EF 24-70mm f/2.8L II USM
ISO: 800
Shutter Speed: 1/500
Aperture: f/4.0
Focal Length: 35mm
Flash: Off

[GPS Coordinates (if present)]
    Latitude: 34.0522° N
    Longitude: -118.2437° W
    Altitude: 45 meters
    Timestamp: 2024-01-15 14:32:00 UTC

[Image Properties]
    Dimensions: 6016 × 4016 pixels
    Color Space: sRGB
    Creation Date: 2024-01-15

[Thumbnail]
    Embedded: Yes (120 × 90 pixels)
```

### Output Example (Document)

```
File: report.docx
Type: Microsoft Word Document (ZIP archive)

[Document Metadata]
===================================
Title: 2024 Security Assessment
Author: John Smith
Created: 2024-01-10 10:30:00 UTC
Modified: 2024-01-15 14:15:00 UTC
Subject: Annual Compliance Review
Keywords: security, audit, Q1
Description: Preliminary findings from network assessment

[Office Document Properties]
    Company: Acme Corp
    Manager: Jane Doe
    Last Modified By: j.smith
    Total Editing Time: 4 hours 23 minutes
    Page Count: 42
```

### Output Example (Archive)

```
File: backup.zip
Type: ZIP Archive

[Archive Structure]
===================================
Compression: DEFLATE (most files)
Total Files: 127
Total Compressed: 45 MB
Total Uncompressed: 120 MB
Compression Ratio: 37.5%

[File Listing (first 20)]
    config.ini (12 KB) - not compressed
    database.sqlite (45 MB) - DEFLATE
    logs/
    logs/2024-01-15.log (2.3 MB) - DEFLATE
    ...

[Hidden Files/Folders]
    .env (discovered!)
    .git/config (discovered!)
```

### Requirements

- Python 3.8+
- os (standard)
- json (standard)
- struct (standard)
- pathlib (standard)
- mimetypes (standard)
- dataclasses (standard)

### EXIF Tags Extracted

Primary tags:
- **0x010F**: Manufacturer
- **0x0110**: Model
- **0x0132**: DateTime
- **0x0213**: YCbCr Positioning
- **0x8825**: GPS IFD Pointer
- **0x9003**: DateTimeOriginal
- **0x9004**: DateTimeDigitized
- **0xA002**: PixelXDimension
- **0xA003**: PixelYDimension

### Notes

- EXIF GPS coordinates in degrees/minutes/seconds format; conversion to decimal implemented
- PDF metadata extraction is text-based; encrypted PDFs may return minimal data
- Office document metadata accessed via core.xml and custom.xml ZIP entries
- ZIP recursive extraction limited to max 5 levels (prevents infinite loops on malicious archives)
- File modification times are UTC; system locale not applied
- TIFF big-endian (MM) and little-endian (II) byte orders both supported

### Common Issues & Workarounds

- **No EXIF found**: Not all JPEGs contain EXIF; some cameras strip it
- **GPS shows 0,0**: Many devices disable GPS or coordinates not recorded
- **PDF metadata empty**: User stripped metadata; PDF structure parsing fails on corrupted PDFs
- **Archive not parsed**: ZIP file may be corrupted; test with `unzip -t archive.zip`
- **Permission denied**: Read permissions required; ensure file access

### OSINT Applications

1. **Photo Intelligence**: Extract camera metadata from leaked images for timeline analysis
2. **Document Attribution**: Identify document authors from embedded metadata
3. **Archive Analysis**: Discover hidden files and structure in backup collections
4. **Timestamp Correlation**: Cross-reference creation dates across evidence

### Limitations

- Does not support:
  - Encrypted DOCX/XLSX (requires password)
  - RAW image formats (CR2, DNG, NEF) - basic binary headers only
  - Embedded object streams in PDF (advanced streams skipped)
  - EXIF maker notes (proprietary formats)
  - Video metadata (MP4, MOV, AVI)
- Recursive extraction limited to prevent DoS via nested archives
- Large archives (>500 MB) may consume significant memory

### Performance

- Small files (<10 MB): <100ms
- Large archives (100+ MB): 1-5 seconds
- Recursive directory scan (1000 files): 5-10 seconds
- Memory usage: ~2× largest uncompressed file size

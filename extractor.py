#!/usr/bin/env python3

import os
import sys
import json
import struct
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import argparse
import mimetypes

class MetadataExtractor:
    """Extract metadata from various file types"""
    
    def __init__(self):
        self.metadata = {}
        self.artifacts = []
    
    def extract_exif(self, image_path: str) -> Dict[str, Any]:
        """Extract EXIF data from images"""
        metadata = {
            'file': os.path.basename(image_path),
            'type': 'JPEG/EXIF',
            'exif_data': {}
        }
        
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
            
            # Basic JPEG/EXIF parsing
            if data[:3] == b'\xff\xd8\xff':
                jpeg_markers = self._find_jpeg_markers(data)
                metadata['exif_data']['markers'] = jpeg_markers
                
                # Look for common EXIF tags
                if b'Exif\x00\x00' in data:
                    exif_offset = data.find(b'Exif\x00\x00') + 6
                    metadata['exif_data']['exif_found'] = True
                    
                    # Try to extract GPS data
                    if b'GPS' in data:
                        metadata['exif_data']['gps_data'] = 'Found'
                    
                    # Try to extract camera info
                    if b'Model' in data or b'Make' in data:
                        metadata['exif_data']['camera_info'] = 'Available'
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def extract_pdf_metadata(self, pdf_path: str) -> Dict[str, Any]:
        """Extract metadata from PDF files"""
        metadata = {
            'file': os.path.basename(pdf_path),
            'type': 'PDF',
            'properties': {}
        }
        
        try:
            with open(pdf_path, 'rb') as f:
                data = f.read(4096)
            
            # Check for PDF
            if data.startswith(b'%PDF'):
                pdf_version = data[:8].decode('utf-8', errors='ignore')
                metadata['pdf_version'] = pdf_version
                
                # Look for document information
                if b'/Producer' in data:
                    metadata['properties']['producer'] = 'Found'
                
                if b'/Creator' in data:
                    metadata['properties']['creator'] = 'Found'
                
                if b'/Author' in data:
                    metadata['properties']['author'] = 'Found'
                
                if b'/CreationDate' in data:
                    metadata['properties']['creation_date'] = 'Found'
                
                if b'/ModDate' in data:
                    metadata['properties']['modification_date'] = 'Found'
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def extract_zip_metadata(self, zip_path: str) -> Dict[str, Any]:
        """Extract metadata from ZIP archives"""
        metadata = {
            'file': os.path.basename(zip_path),
            'type': 'ZIP',
            'files': [],
            'compression_info': {}
        }
        
        try:
            with open(zip_path, 'rb') as f:
                data = f.read()
            
            if data[:4] == b'PK\x03\x04':
                metadata['zip_valid'] = True
                
                # Count local file headers
                local_headers = data.count(b'PK\x03\x04')
                central_headers = data.count(b'PK\x01\x02')
                end_records = data.count(b'PK\x05\x06')
                
                metadata['compression_info']['local_headers'] = local_headers
                metadata['compression_info']['central_headers'] = central_headers
                metadata['compression_info']['end_records'] = end_records
                
                # Look for suspicious patterns
                if b'PK\x00\x00' in data:
                    metadata['suspicious_patterns'] = ['Empty descriptor found']
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def extract_document_metadata(self, doc_path: str) -> Dict[str, Any]:
        """Extract metadata from Office documents"""
        metadata = {
            'file': os.path.basename(doc_path),
            'type': 'Office Document'
        }
        
        try:
            with open(doc_path, 'rb') as f:
                data = f.read(8192)
            
            # Check for OLE2/DOCX formats
            if data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                metadata['format'] = 'OLE2 (DOC/XLS)'
                metadata['major_version'] = struct.unpack('<H', data[24:26])[0]
                metadata['minor_version'] = struct.unpack('<H', data[26:28])[0]
            
            elif data[:2] == b'PK':
                metadata['format'] = 'OOXML (DOCX/XLSX)'
                
                # Look for document.xml
                if b'docProps' in data:
                    metadata['has_core_props'] = True
                
                if b'customProps' in data:
                    metadata['has_custom_props'] = True
            
            # Look for common metadata strings
            metadata_indicators = [
                (b'Author', 'Author'),
                (b'Title', 'Title'),
                (b'Subject', 'Subject'),
                (b'Keywords', 'Keywords'),
                (b'Creator', 'Creator'),
            ]
            
            found_metadata = []
            for indicator, label in metadata_indicators:
                if indicator in data:
                    found_metadata.append(label)
            
            metadata['detected_fields'] = found_metadata
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def extract_image_metadata(self, image_path: str) -> Dict[str, Any]:
        """Extract basic image metadata"""
        metadata = {
            'file': os.path.basename(image_path),
            'type': 'Image'
        }
        
        try:
            stat = os.stat(image_path)
            metadata['file_size'] = stat.st_size
            metadata['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
            metadata['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            with open(image_path, 'rb') as f:
                header = f.read(12)
            
            if header[:8] == b'\x89PNG\r\n\x1a\n':
                metadata['format'] = 'PNG'
                metadata['mime_type'] = 'image/png'
            
            elif header[:3] == b'\xff\xd8\xff':
                metadata['format'] = 'JPEG'
                metadata['mime_type'] = 'image/jpeg'
            
            elif header[:4] == b'GIF8':
                metadata['format'] = 'GIF'
                metadata['mime_type'] = 'image/gif'
            
            elif header[:4] == b'RIFF':
                metadata['format'] = 'BMP/WAV'
                metadata['mime_type'] = 'image/bmp'
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _find_jpeg_markers(self, data: bytes) -> List[str]:
        """Find JPEG markers"""
        markers = []
        jpeg_markers = {
            0xFFD8: 'SOI', 0xFFDB: 'DQT', 0xFFC0: 'SOF0',
            0xFFE0: 'APP0', 0xFFE1: 'EXIF', 0xFFE2: 'APP2',
            0xFFDD: 'DRI', 0xFFDA: 'SOS', 0xFFD9: 'EOI'
        }
        
        for i in range(len(data) - 1):
            marker = (data[i] << 8) | data[i+1]
            if marker in jpeg_markers:
                markers.append(jpeg_markers[marker])
        
        return markers[:5]
    
    def process_file(self, file_path: str) -> Dict[str, Any]:
        """Process file and extract metadata"""
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        
        mime_type, _ = mimetypes.guess_type(file_path)
        
        metadata = {
            'path': file_path,
            'name': os.path.basename(file_path),
            'mime_type': mime_type,
            'file_size': os.path.getsize(file_path),
            'timestamp': datetime.now().isoformat()
        }
        
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext in ['.jpg', '.jpeg']:
            metadata.update(self.extract_exif(file_path))
        
        elif file_ext == '.pdf':
            metadata.update(self.extract_pdf_metadata(file_path))
        
        elif file_ext == '.zip' or file_ext == '.jar':
            metadata.update(self.extract_zip_metadata(file_path))
        
        elif file_ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            metadata.update(self.extract_document_metadata(file_path))
        
        elif file_ext in ['.png', '.gif', '.bmp']:
            metadata.update(self.extract_image_metadata(file_path))
        
        return metadata
    
    def process_directory(self, directory: str) -> List[Dict[str, Any]]:
        """Process all files in directory"""
        results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    metadata = self.process_file(file_path)
                    results.append(metadata)
                except Exception as e:
                    pass
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Metadata Extractor & Artifact Recovery')
    parser.add_argument('path', help='File or directory path')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursive directory processing')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    extractor = MetadataExtractor()
    
    if os.path.isdir(args.path):
        print(f"[*] Processing directory: {args.path}")
        results = extractor.process_directory(args.path)
    else:
        print(f"[*] Processing file: {args.path}")
        results = [extractor.process_file(args.path)]
    
    print(f"\n[+] Processed {len(results)} files")
    
    for result in results:
        if args.verbose:
            print(f"\n{result['name']}:")
            for key, value in result.items():
                if key != 'name':
                    print(f"  {key}: {value}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")

if __name__ == '__main__':
    main()

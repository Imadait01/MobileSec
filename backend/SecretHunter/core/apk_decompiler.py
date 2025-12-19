"""
APK Decompiler Module
Automatically detects and decompiles APK files for secret scanning.
Supports apktool, jadx, and androguard for comprehensive analysis.
"""

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Dict, List


class APKDecompiler:
    """Handles APK file detection, extraction, and decompilation."""
    
    def __init__(self, apk_path: str, output_dir: Optional[str] = None):
        """
        Initialize APK decompiler.
        
        Args:
            apk_path: Path to the APK file
            output_dir: Optional output directory for decompiled files
        """
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir) if output_dir else None
        self.decompiled_path = None
        self.tools_available = self._check_available_tools()
        
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        if not self.apk_path.suffix.lower() == '.apk':
            raise ValueError(f"Not an APK file: {apk_path}")
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which decompilation tools are available."""
        tools = {}
        
        # Check apktool
        try:
            result = subprocess.run(['apktool', '--version'], 
                                   capture_output=True, 
                                   timeout=5)
            tools['apktool'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools['apktool'] = False
        
        # Check jadx
        try:
            result = subprocess.run(['jadx', '--version'], 
                                   capture_output=True, 
                                   timeout=5)
            tools['jadx'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools['jadx'] = False
        
        # Check androguard (Python library)
        try:
            import androguard
            tools['androguard'] = True
        except ImportError:
            tools['androguard'] = False
        
        return tools
    
    def _create_output_dir(self) -> Path:
        """Create output directory for decompiled files."""
        if self.output_dir:
            output_path = self.output_dir
        else:
            # Create temp directory or use apk name
            apk_name = self.apk_path.stem
            output_path = self.apk_path.parent / f"{apk_name}_decompiled"
        
        output_path.mkdir(parents=True, exist_ok=True)
        return output_path
    
    def _extract_apk_as_zip(self, output_path: Path) -> bool:
        """
        Extract APK as ZIP to get raw resources.
        This gives us AndroidManifest.xml (binary), resources, assets, lib, etc.
        """
        try:
            zip_extract_path = output_path / "apk_raw"
            zip_extract_path.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(zip_extract_path)
            
            print(f"[APK] Raw APK contents extracted to: {zip_extract_path}")
            return True
        except Exception as e:
            print(f"[APK] Error extracting APK as ZIP: {e}")
            return False
    
    def _decompile_with_apktool(self, output_path: Path) -> bool:
        """
        Decompile APK using apktool.
        This gives us decoded resources (readable XML), smali code, etc.
        """
        if not self.tools_available.get('apktool', False):
            print("[APK] apktool not available, skipping apktool decompilation")
            return False
        
        try:
            apktool_output = output_path / "apktool_output"
            apktool_output.mkdir(parents=True, exist_ok=True)
            
            cmd = [
                'apktool', 'd', 
                str(self.apk_path), 
                '-o', str(apktool_output),
                '-f'  # force overwrite
            ]
            
            print(f"[APK] Running apktool decompilation...")
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minutes max
            )
            
            if result.returncode == 0:
                print(f"[APK] apktool decompilation successful: {apktool_output}")
                return True
            else:
                print(f"[APK] apktool failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("[APK] apktool decompilation timed out")
            return False
        except Exception as e:
            print(f"[APK] Error running apktool: {e}")
            return False
    
    def _decompile_with_jadx(self, output_path: Path) -> bool:
        """
        Decompile APK using jadx.
        This gives us Java source code from DEX files.
        """
        if not self.tools_available.get('jadx', False):
            print("[APK] jadx not available, skipping jadx decompilation")
            return False
        
        try:
            jadx_output = output_path / "jadx_output"
            jadx_output.mkdir(parents=True, exist_ok=True)
            
            cmd = [
                'jadx', 
                str(self.apk_path), 
                '-d', str(jadx_output),
                '--no-res',  # Skip resources (handled by apktool)
                '--no-imports'  # Simplify output
            ]
            
            print(f"[APK] Running jadx decompilation...")
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=600  # 10 minutes max
            )
            
            if result.returncode == 0:
                print(f"[APK] jadx decompilation successful: {jadx_output}")
                return True
            else:
                print(f"[APK] jadx completed with warnings (common): {jadx_output}")
                # jadx often returns non-zero even on success
                return jadx_output.exists() and any(jadx_output.iterdir())
                
        except subprocess.TimeoutExpired:
            print("[APK] jadx decompilation timed out")
            return False
        except Exception as e:
            print(f"[APK] Error running jadx: {e}")
            return False
    
    def _extract_strings_from_dex(self, output_path: Path) -> bool:
        """
        Extract strings from DEX files using androguard.
        This captures hardcoded strings that might contain secrets.
        """
        if not self.tools_available.get('androguard', False):
            print("[APK] androguard not available, skipping DEX string extraction")
            return False
        
        try:
            from androguard.core.apk import APK
            from androguard.core.dex import DEX
            
            strings_output = output_path / "dex_strings"
            strings_output.mkdir(parents=True, exist_ok=True)
            
            print(f"[APK] Extracting strings from DEX files...")
            
            apk = APK(str(self.apk_path))
            
            # Get all DEX files
            all_strings = set()
            for dex_file in apk.get_all_dex():
                dex = DEX(dex_file)
                strings = dex.get_strings()
                all_strings.update(strings)
            
            # Write strings to file
            strings_file = strings_output / "all_strings.txt"
            with open(strings_file, 'w', encoding='utf-8', errors='ignore') as f:
                for s in sorted(all_strings):
                    f.write(f"{s}\n")
            
            print(f"[APK] Extracted {len(all_strings)} unique strings to: {strings_file}")
            return True
            
        except Exception as e:
            print(f"[APK] Error extracting DEX strings: {e}")
            return False
    
    def decompile(self) -> Optional[Path]:
        """
        Decompile the APK using all available tools.
        
        Returns:
            Path to decompiled directory, or None if all methods failed
        """
        print(f"\n{'='*60}")
        print(f"APK Decompiler - Starting Analysis")
        print(f"{'='*60}")
        print(f"APK File: {self.apk_path}")
        print(f"Available tools: {[k for k, v in self.tools_available.items() if v]}")
        
        if not any(self.tools_available.values()):
            print("\n[ERROR] No decompilation tools available!")
            print("Please install at least one of:")
            print("  - apktool: sudo apt install apktool")
            print("  - jadx: sudo apt install jadx")
            print("  - androguard: pip install androguard")
            return None
        
        # Create output directory
        output_path = self._create_output_dir()
        print(f"Output directory: {output_path}")
        
        # Track success of each method
        results = {}
        
        # Method 1: Extract raw APK (always works)
        print(f"\n[1/4] Extracting raw APK contents...")
        results['raw'] = self._extract_apk_as_zip(output_path)
        
        # Method 2: apktool (for resources and smali)
        print(f"\n[2/4] Decompiling with apktool...")
        results['apktool'] = self._decompile_with_apktool(output_path)
        
        # Method 3: jadx (for Java source)
        print(f"\n[3/4] Decompiling with jadx...")
        results['jadx'] = self._decompile_with_jadx(output_path)
        
        # Method 4: Extract DEX strings
        print(f"\n[4/4] Extracting strings from DEX...")
        results['strings'] = self._extract_strings_from_dex(output_path)
        
        # Summary
        print(f"\n{'='*60}")
        print(f"APK Decompilation Summary")
        print(f"{'='*60}")
        for method, success in results.items():
            status = "✓ Success" if success else "✗ Failed"
            print(f"{method:15} : {status}")
        
        if any(results.values()):
            self.decompiled_path = output_path
            print(f"\nDecompiled APK available at: {output_path}")
            print(f"Ready for secret scanning!")
            return output_path
        else:
            print(f"\n[ERROR] All decompilation methods failed")
            return None
    
    def get_scannable_paths(self) -> List[Path]:
        """
        Get list of directories to scan for secrets.
        
        Returns:
            List of paths to scan
        """
        if not self.decompiled_path:
            return []
        
        paths = []
        
        # Add all subdirectories that were created
        for subdir in ['apk_raw', 'apktool_output', 'jadx_output', 'dex_strings']:
            path = self.decompiled_path / subdir
            if path.exists():
                paths.append(path)
        
        return paths
    
    def cleanup(self):
        """Remove decompiled files (optional cleanup)."""
        if self.decompiled_path and self.decompiled_path.exists():
            try:
                shutil.rmtree(self.decompiled_path)
                print(f"[APK] Cleaned up: {self.decompiled_path}")
            except Exception as e:
                print(f"[APK] Error cleaning up: {e}")


def is_apk_file(file_path: str) -> bool:
    """Check if a file is an APK."""
    return Path(file_path).suffix.lower() == '.apk'

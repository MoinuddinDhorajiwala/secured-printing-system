import os
import shutil
import tempfile
import subprocess
import fitz  # PyMuPDF
import win32print
import win32api
import win32ui
import win32con
from PIL import Image, ImageWin

# ==========================
# 1. Add watermark to PDF
# ==========================
def add_watermark(input_pdf, output_pdf, watermark_text=""):
    if not watermark_text:
        # No watermark
        os.replace(input_pdf, output_pdf)
        return

    doc = fitz.open(input_pdf)
    for page in doc:
        rect = page.rect
        # Define a rectangle in the center
        r = fitz.Rect(rect.width/4, rect.height/2 - 50, rect.width*3/4, rect.height/2 + 50)
        page.insert_textbox(
            r,
            watermark_text,
            fontsize=50,
            rotate=90,       # degrees
            color=(0.8, 0.1, 0.1),
            align=1,         # center
            render_mode=3,   # fill
        )
    doc.save(output_pdf)
    doc.close()


# ==========================
# 2. Extract page range
# ==========================
def extract_pages(input_pdf, output_pdf, page_range=""):
    if not page_range:
        os.replace(input_pdf, output_pdf)
        return

    doc = fitz.open(input_pdf)
    new_doc = fitz.open()

    ranges = page_range.split(",")
    for r in ranges:
        if "-" in r:
            start, end = map(int, r.split("-"))
            for i in range(start - 1, end):
                new_doc.insert_pdf(doc, from_page=i, to_page=i)
        else:
            i = int(r) - 1
            new_doc.insert_pdf(doc, from_page=i, to_page=i)

    new_doc.save(output_pdf)
    new_doc.close()
    doc.close()


# ==========================
# 3. Print PDF
# ==========================
def print_pdf(pdf_file, printer_name=None, copies=1, dpi=300, duplex=False):
    """
    Native Windows printing without requiring an external PDF reader.
    Renders each PDF page to a bitmap (via PyMuPDF) and draws to the
    printer device context using GDI.
    """
    pdf_file = os.path.abspath(pdf_file)
    if not os.path.exists(pdf_file):
        raise FileNotFoundError(f"PDF not found: {pdf_file}")

    try:
        copies = max(1, int(copies))
    except Exception:
        copies = 1

    # Resolve printer
    if not printer_name:
        printer_name = win32print.GetDefaultPrinter()
    else:
        names = [p[2] for p in win32print.EnumPrinters(2)]
        if printer_name not in names:
            raise RuntimeError(f"Printer not found: {printer_name}")

    # Create printer DC
    hDC = win32ui.CreateDC()
    hDC.CreatePrinterDC(printer_name)

    # Configure duplex printing if enabled
    if duplex:
        try:
            # Get printer handle for configuration
            printer_handle = win32print.OpenPrinter(printer_name)
            try:
                # Get current printer settings
                printer_info = win32print.GetPrinter(printer_handle, 2)
                devmode = printer_info['pDevMode']
                
                # Set duplex printing
                if devmode:
                    devmode.Duplex = 2  # DMDUP_VERTICAL (long edge binding)
                    
                    # Update printer settings
                    win32print.SetPrinter(printer_handle, 2, printer_info, 0)
                    print(f"✅ Duplex printing enabled for {printer_name}")
                else:
                    print(f"⚠️  Could not configure duplex: Device mode not available")
            finally:
                win32print.ClosePrinter(printer_handle)
        except Exception as e:
            print(f"⚠️  Could not configure duplex printing: {e}")
            print("   Continuing with single-sided printing...")

    # Printable area (in pixels)
    HORZRES = hDC.GetDeviceCaps(win32con.HORZRES)
    VERTRES = hDC.GetDeviceCaps(win32con.VERTRES)

    # Document
    doc_name = os.path.basename(pdf_file)
    hDC.StartDoc(doc_name)

    doc = fitz.open(pdf_file)
    try:
        for _ in range(copies):
            for page in doc:
                # Render page to bitmap
                zoom = dpi / 72.0
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat, alpha=False)
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

                # Compute scale to fit into printable area while maintaining aspect ratio
                scale = min(HORZRES / img.width, VERTRES / img.height)
                target_w = int(img.width * scale)
                target_h = int(img.height * scale)
                if target_w <= 0 or target_h <= 0:
                    target_w, target_h = img.width, img.height
                img = img.resize((target_w, target_h), Image.LANCZOS)

                # Center the image on the page
                x = (HORZRES - target_w) // 2
                y = (VERTRES - target_h) // 2

                hDC.StartPage()
                dib = ImageWin.Dib(img)
                dib.draw(hDC.GetHandleOutput(), (x, y, x + target_w, y + target_h))
                hDC.EndPage()
    finally:
        hDC.EndDoc()
        hDC.DeleteDC()
        doc.close()


# ==========================
# 4. Main workflow
# ==========================
if __name__ == "__main__":
    print("=== Custom PDF Printing ===\n")

    # Input PDF
    input_pdf = input("Enter full path of PDF file: ").strip()
    if not os.path.exists(input_pdf):
        print("❌ File does not exist. Exiting.")
        exit()

    # List available printers
    printers = [p[2] for p in win32print.EnumPrinters(2)]
    print("\nAvailable Printers:")
    for i, p in enumerate(printers):
        print(f"{i+1}. {p}")
    printer_choice = input("Choose printer number (default 1): ").strip()
    printer_name = printers[int(printer_choice)-1] if printer_choice else printers[0]

    # Page range
    page_range = input("Enter page range (e.g., 1-3,5) or leave empty for all: ").strip()

    # Watermark
    watermark = input("Enter watermark text (leave empty for none): ").strip()

    # Scaling factor
    scale_input = input("Enter scaling factor (default 1.0): ").strip()
    scale = float(scale_input) if scale_input else 1.0

    # Orientation
    orientation_input = input("Choose orientation (portrait/landscape, default portrait): ").strip().lower()
    orientation = orientation_input if orientation_input in ["portrait", "landscape"] else "portrait"

    # Temporary files
    temp_dir = tempfile.gettempdir()
    watermarked_pdf = os.path.join(temp_dir, "watermarked.pdf")
    extracted_pdf = os.path.join(temp_dir, "final_print.pdf")

    # Step 1: Add watermark
    add_watermark(input_pdf, watermarked_pdf, watermark)

    # Step 2: Extract pages
    extract_pages(watermarked_pdf, extracted_pdf, page_range)

    # Step 3: Print
    print_pdf(extracted_pdf, printer_name, copies=1, duplex=False)

    print(f"\n✅ PDF sent to printer '{printer_name}' successfully!")

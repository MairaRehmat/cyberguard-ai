import base64
import os
from pathlib import Path
from typing import Type
from io import BytesIO

from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from openai import OpenAI
from PIL import Image


# ============================================================
# INPUT SCHEMA
# ============================================================

class ScreenshotAnalysisInput(BaseModel):

    image_path: str = Field(
        ...,
        description="Full path of the screenshot to analyze."
    )


# ============================================================
# SCREENSHOT TOOL
# ============================================================

class ScreenshotAnalysisTool(BaseTool):

    name: str = "screenshot_analysis_tool"

    description: str = (
        "Extracts visible text from a cybersecurity screenshot. "
        "It does not classify the message."
    )

    args_schema: Type[BaseModel] = ScreenshotAnalysisInput

    def _run(self, image_path: str) -> dict:

        try:

            # ==================================================
            # API KEY
            # ==================================================

            api_key = (
                os.getenv("OPENROUTER_API_KEY")
                or os.getenv("OPENAI_API_KEY")
            )

            if not api_key:
                return {
                    "success": False,
                    "text": "",
                    "error": (
                        "API key not found. "
                        "Set OPENROUTER_API_KEY in your .env file."
                    )
                }

            # ==================================================
            # CHECK IMAGE
            # ==================================================

            path = Path(image_path)

            if not path.exists():
                return {
                    "success": False,
                    "text": "",
                    "error": f"Image file not found: {image_path}"
                }

            if not path.is_file():
                return {
                    "success": False,
                    "text": "",
                    "error": f"Image path is not a file: {image_path}"
                }

            # ==================================================
            # CHECK IMAGE FORMAT
            # ==================================================

            extension = path.suffix.lower()

            supported_formats = {
                ".png": "image/jpeg",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".webp": "image/jpeg",
            }

            if extension not in supported_formats:
                return {
                    "success": False,
                    "text": "",
                    "error": (
                        f"Unsupported image format: {extension}. "
                        "Use PNG, JPG, JPEG or WEBP."
                    )
                }

            # ==================================================
            # READ + OPTIMIZE IMAGE
            # ==================================================

            image_bytes = path.read_bytes()

            if not image_bytes:
                return {
                    "success": False,
                    "text": "",
                    "error": "The uploaded image is empty."
                }

            image = Image.open(BytesIO(image_bytes))

            # Convert to RGB for JPEG
            if image.mode != "RGB":
                image = image.convert("RGB")

            # --------------------------------------------------
            # Resize only if image is very large
            # --------------------------------------------------

            max_dimension = 1800

            if max(image.width, image.height) > max_dimension:

                ratio = max_dimension / max(
                    image.width,
                    image.height
                )

                new_width = int(image.width * ratio)
                new_height = int(image.height * ratio)

                image = image.resize(
                    (new_width, new_height),
                    Image.Resampling.LANCZOS
                )

            # ==================================================
            # COMPRESS IMAGE
            # ==================================================

            optimized_buffer = BytesIO()

            image.save(
                optimized_buffer,
                format="JPEG",
                quality=85,
                optimize=True
            )

            optimized_bytes = optimized_buffer.getvalue()

            encoded_image = base64.b64encode(
                optimized_bytes
            ).decode("utf-8")

            mime_type = "image/jpeg"

            # ==================================================
            # OPENROUTER
            # ==================================================

            base_url = os.getenv(
                "OPENAI_BASE_URL",
                "https://openrouter.ai/api/v1"
            )

            vision_model = os.getenv(
                "VISION_MODEL",
                "google/gemini-2.5-flash"
            )

            print("--------------------------------------------")
            print("SCREENSHOT ANALYSIS")
            print(f"Original image: {path}")
            print(
                f"Original size: "
                f"{image_bytes.__len__() / 1024:.1f} KB"
            )
            print(
                f"Optimized size: "
                f"{optimized_bytes.__len__() / 1024:.1f} KB"
            )
            print(f"Model: {vision_model}")
            print(f"Base URL: {base_url}")
            print("--------------------------------------------")

            client = OpenAI(
                api_key=api_key,
                base_url=base_url,
            )

            # ==================================================
            # PROMPT
            # ==================================================

            prompt = """
You are an OCR-style text extraction system.

Read the uploaded screenshot carefully.

Extract ONLY the text that is visibly present in the image.

Requirements:

- Preserve the original wording as accurately as possible.
- Preserve URLs.
- Preserve email addresses.
- Preserve phone numbers.
- Preserve OTPs and verification codes.
- Preserve dates.
- Preserve monetary amounts.
- Preserve important punctuation.
- Keep the extracted text in readable order.

Do NOT:
- classify the message
- call it safe
- call it suspicious
- call it dangerous
- provide cybersecurity advice
- explain the screenshot
- describe colors or UI
- invent missing text

Return ONLY the visible text.
"""

            # ==================================================
            # VISION REQUEST
            # ==================================================

            response = client.chat.completions.create(

                model=vision_model,

                messages=[
                    {
                        "role": "user",

                        "content": [

                            {
                                "type": "text",
                                "text": prompt,
                            },

                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": (
                                        f"data:{mime_type};"
                                        f"base64,{encoded_image}"
                                    )
                                },
                            },
                        ],
                    }
                ],

                # Keep enough room for screenshot text
                max_tokens=200,

                temperature=0,
            )

            # ==================================================
            # RESPONSE CHECK
            # ==================================================

            if not response.choices:
                return {
                    "success": False,
                    "text": "",
                    "error": "OpenRouter returned no choices."
                }

            message = response.choices[0].message

            text = message.content or ""
            text = str(text).strip()

            # ==================================================
            # EMPTY RESPONSE
            # ==================================================

            if not text:
                return {
                    "success": False,
                    "text": "",
                    "error": (
                        "Vision model returned an empty response."
                    )
                }

            # ==================================================
            # REMOVE MARKDOWN FENCES
            # ==================================================

            if text.startswith("```"):

                lines = text.splitlines()

                if len(lines) >= 2:
                    lines = lines[1:]

                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]

                text = "\n".join(lines).strip()

            # ==================================================
            # SUCCESS
            # ==================================================

            print("Extracted screenshot text:")
            print(text)
            print("--------------------------------------------")

            return {
                "success": True,
                "text": text,
                "error": "",
            }

        # ======================================================
        # ERROR
        # ======================================================

        except Exception as e:

            error_message = str(e)

            print("--------------------------------------------")
            print("SCREENSHOT ANALYSIS ERROR")
            print(error_message)
            print("--------------------------------------------")

            return {
                "success": False,
                "text": "",
                "error": error_message,
            }

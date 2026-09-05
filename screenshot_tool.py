import base64
import os
from pathlib import Path
from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from openai import OpenAI


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
            # READ IMAGE
            # ==================================================

            image_bytes = path.read_bytes()

            if not image_bytes:

                return {
                    "success": False,
                    "text": "",
                    "error": "The uploaded image is empty."
                }

            encoded_image = base64.b64encode(
                image_bytes
            ).decode("utf-8")

            # ==================================================
            # MIME TYPE
            # ==================================================

            extension = path.suffix.lower()

            mime_types = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".webp": "image/webp",
            }

            mime_type = mime_types.get(extension)

            if not mime_type:

                return {
                    "success": False,
                    "text": "",
                    "error": (
                        f"Unsupported image format: {extension}. "
                        "Use PNG, JPG, JPEG or WEBP."
                    )
                }

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
            print(f"Image: {path}")
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
                    "error": (
                        "OpenRouter returned no choices."
                    )
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

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

    def _run(
        self,
        image_path: str
    ) -> dict:

        try:

            # ------------------------------------------------
            # API KEY
            # ------------------------------------------------

            api_key = (
                os.getenv("OPENROUTER_API_KEY")
                or os.getenv("OPENAI_API_KEY")
            )

            if not api_key:

                return {
                    "success": False,
                    "text": "",
                    "error": (
                        "OPENROUTER_API_KEY or OPENAI_API_KEY "
                        "was not found."
                    )
                }

            # ------------------------------------------------
            # CHECK FILE
            # ------------------------------------------------

            path = Path(image_path)

            if not path.exists():

                return {
                    "success": False,
                    "text": "",
                    "error": (
                        f"Image file not found: {image_path}"
                    )
                }

            # ------------------------------------------------
            # READ IMAGE
            # ------------------------------------------------

            image_bytes = path.read_bytes()

            encoded_image = base64.b64encode(
                image_bytes
            ).decode("utf-8")

            # ------------------------------------------------
            # MIME TYPE
            # ------------------------------------------------

            extension = path.suffix.lower()

            mime_types = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".webp": "image/webp",
            }

            mime_type = mime_types.get(
                extension,
                "image/png"
            )

            # ------------------------------------------------
            # OPENROUTER CLIENT
            # ------------------------------------------------

            client = OpenAI(
                api_key=api_key,

                base_url=os.getenv(
                    "OPENAI_BASE_URL",
                    "https://openrouter.ai/api/v1"
                )
            )

            vision_model = os.getenv(
                "VISION_MODEL",
                "google/gemini-2.5-flash"
            )

            # ------------------------------------------------
            # PROMPT
            # ------------------------------------------------

            prompt = """
You are an OCR-style cybersecurity evidence extraction tool.

Read the screenshot carefully and extract ONLY the visible
message/text shown in the screenshot.

Rules:

1. Preserve the wording as accurately as possible.
2. Preserve URLs if visible.
3. Preserve important numbers, OTPs, amounts and dates if visible.
4. Do NOT classify the message.
5. Do NOT say SAFE, SUSPICIOUS or DANGEROUS.
6. Do NOT add cybersecurity advice.
7. Do NOT describe the visual appearance.
8. Do NOT add information that is not visible.
9. Return only the extracted visible text.
"""

            # ------------------------------------------------
            # VISION REQUEST
            # ------------------------------------------------

            response = client.chat.completions.create(

                model=vision_model,

                messages=[
                    {
                        "role": "user",

                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": (
                                        f"data:{mime_type};"
                                        f"base64,{encoded_image}"
                                    )
                                }
                            }
                        ]
                    }
                ],

                max_tokens=1000,

                temperature=0
            )

            # ------------------------------------------------
            # EXTRACT RESPONSE
            # ------------------------------------------------

            text = ""

            if response.choices:

                text = (
                    response
                    .choices[0]
                    .message
                    .content
                    or ""
                )

            text = str(text).strip()

            # Remove accidental markdown fences

            if text.startswith("```"):

                lines = text.splitlines()

                if len(lines) >= 2:

                    lines = lines[1:]

                if lines and lines[-1].strip() == "```":

                    lines = lines[:-1]

                text = "\n".join(lines).strip()

            return {
                "success": True,
                "text": text,
                "error": ""
            }

        except Exception as e:

            print(
                f"Screenshot analysis error: {e}"
            )

            return {
                "success": False,
                "text": "",
                "error": str(e)
            }
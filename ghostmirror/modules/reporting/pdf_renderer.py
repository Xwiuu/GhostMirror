"""PDF Renderer to compile HTML reports into PDF using WeasyPrint."""

from __future__ import annotations

from pathlib import Path
from ghostmirror.core.logger import get_logger

logger = get_logger()


class PDFReportRenderer:
    """Handles PDF rendering with a clean fallback strategy for environments without WeasyPrint libraries."""

    @staticmethod
    def render(html_content: str, output_path: Path | str) -> bool:
        """Compiles HTML into a PDF file.

        Parameters
        ----------
        html_content : str
            The complete HTML document string.
        output_path : Path | str
            The file path to save the PDF.

        Returns
        -------
        bool
            True if PDF was successfully written, False otherwise.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            import weasyprint

            logger.info("PDF_RENDER_START target={}", path)
            weasyprint.HTML(string=html_content).write_pdf(str(path))
            logger.info("PDF_RENDER_SUCCESS target={}", path)
            return True

        except (ImportError, OSError) as exc:
            # Weasyprint python package or its dependencies (Pango, Cairo) are not installed or cannot load
            logger.warning(
                "PDF_RENDER_UNSUPPORTED weasyprint is not installed or libraries cannot be loaded. Fallback to HTML/MD. Error: {}",
                exc,
            )
            print(
                "\n[yellow]Aviso: 'weasyprint' não está disponível no ambiente. O PDF não pôde ser gerado.[/]\n"
                "[dim]Verifique se as dependências do Cairo e Pango estão instaladas no sistema.[/]\n"
            )
            return False

        except Exception as exc:
            # Catching OS errors related to missing libcairo-2, libpango, etc., during execution
            logger.exception("PDF_RENDER_FAILED target={} error={}", path, exc)
            print(
                f"\n[red]Erro ao gerar relatório PDF:[/] {exc}\n"
                "[yellow]Os relatórios HTML e Markdown foram gerados e salvos com sucesso.[/]\n"
            )
            return False

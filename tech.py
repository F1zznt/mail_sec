from pathlib import Path
import warnings
import torch
from transformers import MarianTokenizer, MarianMTModel

_OPUS_DIR = Path(__file__).resolve().parent / "models" / "opus-mt-ru-en"
if _OPUS_DIR.is_dir():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        _tr_tokenizer = MarianTokenizer.from_pretrained(str(_OPUS_DIR), local_files_only=True)
        _tr_model = MarianMTModel.from_pretrained(str(_OPUS_DIR), local_files_only=True)
    _tr_model.eval()
else:
    _tr_tokenizer = _tr_model = None


def tr(text: str) -> str:
    if _tr_tokenizer is None or _tr_model is None:
        return text
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        inputs = _tr_tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=512)
    with torch.no_grad():
        translated_tokens = _tr_model.generate(**inputs, max_length=512, num_beams=4, early_stopping=True)
    return _tr_tokenizer.decode(translated_tokens[0], skip_special_tokens=True)

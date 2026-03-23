from pathlib import Path
from transformers import AutoTokenizer,AutoModelForSequenceClassification,MarianTokenizer,MarianMTModel,

try:
    import sentencepiece
except ImportError:
    import subprocess
    subprocess.check_call(["pip", "install", "sentencepiece", "-q"])
    import sentencepiece

PROJECT_ROOT = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_ROOT / "models"

def install_bert_phishing():
    model_id = "ealvaradob/bert-finetuned-phishing"
    save_path = MODELS_DIR / "bert-finetuned-phishing"
    save_path.mkdir(parents=True, exist_ok=True)
    if (save_path / "config.json").exists():
        print(f"Already installed: {save_path} (skip)")
        return

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    tokenizer.save_pretrained(save_path)
    model.save_pretrained(save_path)

def install_opus_mt_ru_en():
    model_id = "Helsinki-NLP/opus-mt-ru-en"
    save_path = MODELS_DIR / "opus-mt-ru-en"
    save_path.mkdir(parents=True, exist_ok=True)
    if (save_path / "config.json").exists():
        print(f"Already installed: {save_path} (skip)")
        return
    tokenizer = MarianTokenizer.from_pretrained(model_id)
    model = MarianMTModel.from_pretrained(model_id)
    tokenizer.save_pretrained(save_path)
    model.save_pretrained(save_path)



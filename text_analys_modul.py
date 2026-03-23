import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from tech import tr

# bert-finetuned-phishing
MODEL_PATH = str(Path(__file__).resolve().parent / "models" / "bert-finetuned-phishing")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()

def is_phishing(text: str):
    text = text.replace("gonna", "").replace("please", "").replace("'ll", " will").replace("'m", " am").replace("'s", " is")
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]
    return {"phish": float(probs[1].item()), "legit": float(probs[0].item())}
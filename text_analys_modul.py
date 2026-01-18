import torch
from translate import Translator
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_PATH = "./models"
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()

def is_phishing(text: str):
    translator = Translator(from_lang="ru", to_lang="en")
    inputs = tokenizer(translator.translate(text[:450]), return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]
    return {"phish": float(probs[1].item()), "legit": float(probs[0].item())}


if __name__ == "__main__":
    print(is_phishing('''Здравствуйте, Олег!

Ваша заявка на смену учетной записи одобрена.

По всем вопросам: 3754759@urfu.ru.

Вступайте в нашу группу Вконтакте: vk.com/urfu_courses

ФГАОУ ВО "УрФУ имени первого Президента России Б.Н.Ельцина"

Вы можете настроить политику получения подобных уведомлений или полностью от них отписаться'''))

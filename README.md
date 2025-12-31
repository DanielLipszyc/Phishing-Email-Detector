# Phishing-Email-Detector
ML system for detecting phishing emails

To run:
1.) Go to: https://www.kaggle.com/datasets/subhajournal/phishingemails
2.) Download the data set and unzip it
3.) Drag it into the data/ directory and rename "emails.csv"
4.) Run the following commands:

python -c "import pandas as pd; df = pd.read_csv('data/emails.csv'); df = df.rename(columns={'Email Text': 'text', 'Email Type': 'label'}); df.to_csv('data/emails.csv', index=False); print('Done! Columns renamed.')"

python -c "
import pandas as pd
df = pd.read_csv('data/emails.csv')
df['label'] = df['label'].apply(lambda x: 1 if 'Phishing' in str(x) else 0)
df.to_csv('data/emails.csv', index=False)
print('Done! Labels converted to 0 and 1')
print(df['label'].value_counts())
"

5.) run train.py
6.) Model is trained and can be tested by running main.py or your own testing script
7.) Enjoy :)

   

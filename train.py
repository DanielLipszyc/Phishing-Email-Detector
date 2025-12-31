import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from imblearn.over_sampling import SMOTE
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os

from src.feature_extractor import FeatureExtractor


class PhishingModelTrainer:
    """Train and evaluate phishing detection models."""
    
    def __init__(self, data_path):
        self.data_path = data_path
        self.extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        self.best_model = None
        self.feature_names = None
        
    def load_and_prepare_data(self):
        """Load dataset and extract features."""
        
        print("Loading dataset...")
        df = pd.read_csv(self.data_path)
        
        # Adjust column names based on your dataset
        text_col = None
        label_col = None
        
        for col in df.columns:
            col_lower = col.lower()
            if col_lower in ['text', 'email', 'body', 'content', 'email_text', 'message']:
                text_col = col
            if col_lower in ['label', 'class', 'phishing', 'is_phishing', 'target']:
                label_col = col
        
        if not text_col or not label_col:
            print(f"Columns found: {df.columns.tolist()}")
            raise ValueError("Could not identify text and label columns")
        
        print(f"Using '{text_col}' as text column and '{label_col}' as label column")
        print(f"Dataset size: {len(df)} emails")
        print(f"Label distribution:\n{df[label_col].value_counts()}")
        
        # Extract features
        print("\nExtracting features (this may take a few minutes)...")
        features_list = []
        
        for idx, row in df.iterrows():
            if idx % 500 == 0:
                print(f"  Processing email {idx}/{len(df)}...")
            
            features = self.extractor.extract_all_features(str(row[text_col]))
            features_list.append(features)
        
        # Create feature matrix
        self.feature_names = self.extractor.get_feature_names()
        X = pd.DataFrame(features_list)[self.feature_names]
        y = df[label_col].values
        
        # Handle any NaN values
        X = X.fillna(0)
        
        print(f"\nFeature matrix shape: {X.shape}")
        
        return X, y
    
    def train_and_evaluate(self, X, y):
        """Train multiple models and compare performance."""
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Handle class imbalance with SMOTE
        print("\nApplying SMOTE for class balance...")
        smote = SMOTE(random_state=42)
        X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
        print(f"Balanced training set: {len(X_train_balanced)} samples")
        
        # Define models to evaluate
        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100, max_depth=15, random_state=42, n_jobs=-1
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=100, max_depth=5, random_state=42
            ),
            'Logistic Regression': LogisticRegression(
                max_iter=1000, random_state=42
            ),
            'SVM': SVC(
                kernel='rbf', probability=True, random_state=42
            ),
            'K-Nearest Neighbors': KNeighborsClassifier(
                n_neighbors=5, n_jobs=-1
            )
        }
        
        results = {}
        
        print("\n" + "="*60)
        print("MODEL EVALUATION")
        print("="*60)
        
        for name, model in models.items():
            print(f"\n--- {name} ---")
            
            # Train
            model.fit(X_train_balanced, y_train_balanced)
            
            # Predict
            y_pred = model.predict(X_test_scaled)
            y_prob = model.predict_proba(X_test_scaled)[:, 1]
            
            # Evaluate
            accuracy = (y_pred == y_test).mean()
            roc_auc = roc_auc_score(y_test, y_prob)
            
            # Cross-validation
            cv_scores = cross_val_score(
                model, X_train_balanced, y_train_balanced, 
                cv=StratifiedKFold(5), scoring='f1'
            )
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'roc_auc': roc_auc,
                'cv_f1_mean': cv_scores.mean(),
                'cv_f1_std': cv_scores.std(),
                'y_pred': y_pred,
                'y_prob': y_prob
            }
            
            print(f"Accuracy: {accuracy:.4f}")
            print(f"ROC-AUC: {roc_auc:.4f}")
            print(f"CV F1-Score: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Select best model based on ROC-AUC
        best_name = max(results.keys(), key=lambda k: results[k]['roc_auc'])
        self.best_model = results[best_name]['model']
        
        print("\n" + "="*60)
        print(f"BEST MODEL: {best_name}")
        print(f"ROC-AUC: {results[best_name]['roc_auc']:.4f}")
        print("="*60)
        
        return results, X_test_scaled, y_test, best_name
    
    def plot_results(self, results, X_test, y_test, save_dir='models'):
        """Generate evaluation plots."""
        
        os.makedirs(save_dir, exist_ok=True)
        
        # 1. ROC Curves
        plt.figure(figsize=(10, 8))
        for name, res in results.items():
            fpr, tpr, _ = roc_curve(y_test, res['y_prob'])
            plt.plot(fpr, tpr, label=f"{name} (AUC={res['roc_auc']:.3f})")
        
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves - Model Comparison')
        plt.legend()
        plt.savefig(f'{save_dir}/roc_curves.png', dpi=150, bbox_inches='tight')
        plt.close()
        
        # 2. Confusion Matrix for best model
        best_name = max(results.keys(), key=lambda k: results[k]['roc_auc'])
        cm = confusion_matrix(y_test, results[best_name]['y_pred'])
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Legitimate', 'Phishing'],
                    yticklabels=['Legitimate', 'Phishing'])
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.title(f'Confusion Matrix - {best_name}')
        plt.savefig(f'{save_dir}/confusion_matrix.png', dpi=150, bbox_inches='tight')
        plt.close()
        
        # 3. Feature Importance (for tree-based models)
        if hasattr(self.best_model, 'feature_importances_'):
            importance = self.best_model.feature_importances_
            indices = np.argsort(importance)[::-1][:15]
            
            plt.figure(figsize=(10, 8))
            plt.barh(range(len(indices)), importance[indices])
            plt.yticks(range(len(indices)), [self.feature_names[i] for i in indices])
            plt.xlabel('Feature Importance')
            plt.title('Top 15 Most Important Features')
            plt.gca().invert_yaxis()
            plt.savefig(f'{save_dir}/feature_importance.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        print(f"\nPlots saved to {save_dir}/")
    
    def save_model(self, save_dir='models'):
        """Save trained model and scaler."""
        
        os.makedirs(save_dir, exist_ok=True)
        
        joblib.dump(self.best_model, f'{save_dir}/phishing_model.joblib')
        joblib.dump(self.scaler, f'{save_dir}/scaler.joblib')
        joblib.dump(self.feature_names, f'{save_dir}/feature_names.joblib')
        
        print(f"Model saved to {save_dir}/")


def main():
    DATA_PATH = 'data/emails.csv'
    
    trainer = PhishingModelTrainer(DATA_PATH)
    
    # Load and prepare data
    X, y = trainer.load_and_prepare_data()
    
    # Train and evaluate models
    results, X_test, y_test, best_name = trainer.train_and_evaluate(X, y)
    
    # Generate plots
    trainer.plot_results(results, X_test, y_test)
    
    # Save best model
    trainer.save_model()
    
    print("\nTraining complete!")


if __name__ == "__main__":
    main()
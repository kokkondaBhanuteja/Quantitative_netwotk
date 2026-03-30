from django.core.management.base import BaseCommand
from defense.ml_model_trainer_real import RealDefenseRecommender

class Command(BaseCommand):
    help = 'Train ML model on real vulnerability data'

    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.SUCCESS('\n' + '='*80))
        self.stdout.write(self.style.SUCCESS('Starting ML Model Training'))
        self.stdout.write(self.style.SUCCESS('='*80 + '\n'))
        
        recommender = RealDefenseRecommender()
        
        try:
            results = recommender.train_model()
            
            self.stdout.write(self.style.SUCCESS('\n' + '='*80))
            self.stdout.write(self.style.SUCCESS('✅ TRAINING COMPLETED SUCCESSFULLY!'))
            self.stdout.write(self.style.SUCCESS('='*80))
            self.stdout.write(self.style.SUCCESS(f"Train Accuracy: {results['train_accuracy']*100:.2f}%"))
            self.stdout.write(self.style.SUCCESS(f"Test Accuracy: {results['test_accuracy']*100:.2f}%"))
            self.stdout.write(self.style.SUCCESS(f"Training Samples: {results['n_samples']}"))
            self.stdout.write(self.style.SUCCESS('='*80 + '\n'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\n❌ Training failed: {e}'))
            import traceback
            self.stdout.write(self.style.ERROR(traceback.format_exc()))

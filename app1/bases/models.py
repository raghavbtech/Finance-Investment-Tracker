from django.db import models

from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"




class Transaction(models.Model):
    category = models.CharField(max_length=100)
    amount = models.FloatField()
    description = models.CharField(max_length=500, blank=True, null=True)
    user = models.ForeignKey(User,
        on_delete=models.CASCADE,
        related_name='transactions'
    )

    def __str__(self):
        return f"{self.category} - {self.amount}"
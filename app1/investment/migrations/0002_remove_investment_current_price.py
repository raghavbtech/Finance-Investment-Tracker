# Generated by Django 5.2 on 2025-04-04 12:30

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('investment', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='investment',
            name='current_price',
        ),
    ]

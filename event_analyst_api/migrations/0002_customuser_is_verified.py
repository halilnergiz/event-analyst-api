# Generated by Django 5.0.4 on 2024-05-07 17:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('event_analyst_api', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
    ]
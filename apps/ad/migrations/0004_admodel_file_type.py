# Generated by Django 5.0 on 2024-07-30 05:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad', '0003_remove_trendingtag_newspost_tags_admodel_created_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='admodel',
            name='file_type',
            field=models.CharField(choices=[('IMAGE', 'Image'), ('VIDEO', 'Video')], default='IMAGE', max_length=10),
        ),
    ]
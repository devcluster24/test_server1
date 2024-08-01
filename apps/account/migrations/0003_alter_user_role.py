# Generated by Django 5.0 on 2024-07-29 11:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_alter_user_role'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('EDITOR', 'Editor'), ('ADMIN', 'Admin'), ('SUPER_ADMIN', 'Super_Admin')], max_length=12),
        ),
    ]

import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from apps.account.managers import CustomUserManager


class User(AbstractBaseUser, PermissionsMixin):
    class ROLE_TYPE(models.TextChoices):
        EDITOR = 'EDITOR', 'Editor'
        ADMIN = 'ADMIN', 'Admin'
        SUPER_ADMIN = 'SUPER_ADMIN', 'Super_Admin'

    user_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    username = models.CharField(max_length=20)
    first_name = models.CharField(max_length=20)
    last_name = models.CharField(max_length=20)
    email = models.EmailField(unique=True) 
    phone = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)
    profile_picture = models.ImageField(upload_to='account/profile_Image/', blank=True)
    bio = models.TextField(blank=True)
    role = models.CharField(
             max_length=12, choices=ROLE_TYPE.choices
            )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "first_name", "last_name"]

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    objects = CustomUserManager()

    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def get_short_name(self):
        return self.username
    
    def __str__(self):
        return self.username

# class ShareCount

class DashboardStat(models.Model):
    total_post = models.PositiveIntegerField(default=0)
    total_shares = models.PositiveIntegerField(default=0)
    total_editor = models.PositiveIntegerField(default=0)
    todays_post = models.PositiveIntegerField(default=0)
    date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.date 
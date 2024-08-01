from django.db import models
from django.utils import timezone
from apps.account.models import User 
from apps.ad.models import TrendingTag


class Category(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name



class SearchFilter(models.Model):
    division = models.CharField(max_length=100, blank=True)
    district = models.CharField(max_length=100, blank=True)
    upazila = models.CharField(max_length=100, blank=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.district


class Division(models.Model):
    name = models.CharField(max_length=80)

    def __str__(self):
        return self.name
    

class District(models.Model):
    name = models.CharField(max_length=80)
    division = models.ForeignKey(Division, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
    

class Upazila(models.Model):
    name = models.CharField(max_length=80)
    district = models.ForeignKey(District, on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class FilterNews(models.Model):
    division = models.ForeignKey(Division, on_delete=models.CASCADE, blank=True, null=True)
    district = models.ForeignKey(District, on_delete=models.CASCADE, blank=True, null=True)
    upazila = models.ForeignKey(Upazila, on_delete=models.CASCADE, blank=True, null=True)


class Location(models.Model):
    class TYPE(models.TextChoices):
        NATIONAL = 'NATIONAL', 'national'
        INTERNATIONAL = 'INTERNATIONAL', 'international'
    
    location_type = models.CharField(
        max_length=14, choices=TYPE.choices, default=TYPE.NATIONAL
        )
    division = models.CharField(max_length=100)
    district = models.CharField(max_length=100)
    upazila = models.CharField(max_length=100)
    custom_location = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.custom_location


class NewsPost(models.Model):
    headline = models.CharField(max_length=200)
    content = models.TextField()
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    trending_tags = models.ManyToManyField(TrendingTag)
    editor = models.ForeignKey(
        User, on_delete=models.CASCADE, blank=True, null=True
        )
    is_active = models.BooleanField(default=False) 
    location = models.ForeignKey(Location, on_delete=models.CASCADE)
    image = models.URLField(blank=True)
    video = models.URLField(blank=True)
    share_count = models.PositiveIntegerField(default=0)
    photo_editor = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.headline
    



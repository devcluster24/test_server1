from django.db import models
from django.utils import timezone
# Write Navbar models here.


class NavbarLink(models.Model):
    name = models.CharField(max_length=100)
    url = models.URLField()
    order = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class TrendingTag(models.Model):
    tag = models.CharField(max_length=100)
    is_latest = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.tag 


class Banner(models.Model):
    class BANNERPAGETYPE(models.TextChoices):
        HOME = 'HOME', 'Home'
        SEARCH_RESULT = 'SEARCH_RESULT', 'Search_Result'
        NEWS_POST = 'NEWS_POST', 'Newspost'
        CATEGORY = 'CATEGORY', 'Category'
        TRENDINGTAGS = 'TRENDINGTAGS', 'Trendingtags'

    page = models.CharField(max_length=60, choices=BANNERPAGETYPE.choices)
    image = models.URLField()
    link = models.URLField(blank=True)
    height = models.CharField(max_length=20)
    width = models.CharField(max_length=20)
    order = models.PositiveIntegerField() 
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.page


class AdModel(models.Model):
    class ADPAGETYPE(models.TextChoices):
        HOME = 'HOME', 'Home'
        SEARCH_RESULT = 'SEARCH_RESULT', 'Search_Result'
        NEWS_POST = 'NEWS_POST', 'Newspost'
        CATEGORY = 'CATEGORY', 'Category'
        TRENDINGTAGS = 'TRENDINGTAGS', 'Trendingtags'
    
    class FILE_TYPE(models.TextChoices):
        IMAGE = 'IMAGE', 'Image',
        VIDEO = 'VIDEO', 'Video'

    page = models.CharField(max_length=60, choices=ADPAGETYPE.choices)
    section = models.CharField(max_length=100)
    file_type = models.CharField(
        max_length=10, choices=FILE_TYPE.choices, default=FILE_TYPE.IMAGE
        )
    image = models.URLField(blank=True)
    link = models.URLField(blank=True)
    video = models.URLField(blank=True)
    height = models.CharField(max_length=20)
    width = models.CharField(max_length=20)
    order = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.page} --> Section {self.section}"
    

class FooterLink(models.Model):
    name = models.CharField(max_length=100)
    url = models.URLField()
    column = models.PositiveIntegerField()
    order = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Logo(models.Model):
    class TYPE(models.TextChoices):
        NEWSPORTAL = 'NEWSPORTAL', 'Newsportal',
        ADMIN_DASHBOARD = 'ADMIN_DASHBOARD', 'Admin_Dashboard'
 
    portal_type = models.CharField(max_length=15, choices=TYPE.choices)
    is_active = models.BooleanField(default=True)
    image = models.URLField(blank=True)
    height = models.CharField(max_length=20)
    width = models.CharField(max_length=20)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)


class CompanyBanner(models.Model):
    image = models.URLField()
    is_active = models.BooleanField(default=False)
    height = models.CharField(max_length=20)
    width = models.CharField(max_length=20)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
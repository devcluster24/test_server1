from django.contrib import admin
from apps.websiteInformation.models import About, Contact, NewsLetter
# Register your models here.


admin.site.register(About)
admin.site.register(Contact)
admin.site.register(NewsLetter)
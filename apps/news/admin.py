from django.contrib import admin
from apps.news.models import (
                              Category, 
                              Location, 
                              FilterNews, 
                              NewsPost,
                              Division,
                              District, 
                              Upazila
                              )

admin.site.register(Category)
admin.site.register(Location)
admin.site.register(FilterNews)
admin.site.register(NewsPost)
admin.site.register(Division)
admin.site.register(District)
admin.site.register(Upazila)

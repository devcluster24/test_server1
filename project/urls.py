from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from apps.news.views import AllNewsPostAdminViews


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/admin-news/', AllNewsPostAdminViews.as_view(), name='admin-newspost'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth_user/', include('apps.account.urls')),
    path('api/ad/', include('apps.ad.urls')),
    path('api/news/', include('apps.news.urls')),
    path('api/webinfo/', include('apps.websiteInformation.urls'))

]


urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

admin.site.site_header = "Kaler Potro NewsPortal Admin"
admin.site.site_title = "Kaler Potro Admin Portal"
admin.site.index_title = "Welcome to the Kaler Potro Admin Portal"
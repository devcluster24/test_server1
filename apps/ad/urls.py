from django.urls import path
from apps.ad.views import (
                            NavbarLinkListView,
                            NavbarLinkCreateView,
                            NavbarLinkRetrieveUpdateDestroyAPIView,
                            TrendingTagsListView, TrendingTagsCreateViews,
                            TrendingTagsRetrieveUpdateDestroyViews,
                            BannerListView, BannerCreateViews, 
                            BannerRetrieveUpdateDestroyViews,
                            AdListView, AdCreateViews,
                            AdRetrieveUpdateDestroyViews,
                            FooterLinkListView, FooterLinkCreateViews, 
                            FooterLinkRetrieveUpdateDestroyApiViews,
                            LogoCreateView, LogoListView,
                            LogoRetrieveUpdateDestroyView,
                            CompanyBannerListView,
                            CompanyBannerCreateView,
                            CompanyBannerRetrieveUpdateDestroyView
                            )


urlpatterns = [
    path('navbarlinks/', NavbarLinkCreateView.as_view(), name='navbarlink-create'),
    path('navbarlink/list/', NavbarLinkListView.as_view(), name='navbarlink-list'),
    path('navbarlinks/<int:pk>/', NavbarLinkRetrieveUpdateDestroyAPIView.as_view(), name='navbarlink-detail'),
    path('trendingtags/list/', TrendingTagsListView.as_view(), name='trending_tag_list'),
    path('trendingtags/', TrendingTagsCreateViews.as_view(), name='trending_tag_create'),
    path('trendingtags/<int:pk>/', TrendingTagsRetrieveUpdateDestroyViews.as_view(), name='trendingtag_detail'),
    path('banner/list/', BannerListView.as_view(), name="banner-list"),
    path('banner/', BannerCreateViews.as_view(), name="banner-create"),
    path('banner/<int:pk>/', BannerRetrieveUpdateDestroyViews.as_view(), name="banner_detail"),
    path('list/', AdListView.as_view(), name="Ad-list"),
    path('', AdCreateViews.as_view(), name="Ad-create"),
    path('<int:pk>/', AdRetrieveUpdateDestroyViews.as_view(), name="Ad_detail"),
    path('footerlinks/list/', FooterLinkListView.as_view(), name="footer_link_list"),
    path('footerlinks/', FooterLinkCreateViews.as_view(), name="footer_link_create"),
    path('footerlinks/<int:pk>/', FooterLinkRetrieveUpdateDestroyApiViews.as_view(), name="footer_link"),
    path('logo/list/', LogoListView.as_view(), name="logo_list"),
    path('logo/', LogoCreateView.as_view(), name="logo_create"),
    path('logo/<int:pk>/', LogoRetrieveUpdateDestroyView.as_view(), name="company_banner_details"),
    path('companybanner/list/', CompanyBannerListView.as_view(), name="company_banner_list"),
    path('companybanner/', CompanyBannerCreateView.as_view(), name="company_banner_create"),
    path('companybanner/<int:pk>/', CompanyBannerRetrieveUpdateDestroyView.as_view(), name="company_banner_details")
]

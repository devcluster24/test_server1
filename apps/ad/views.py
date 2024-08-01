from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from apps.ad.models import (
                            NavbarLink, 
                            TrendingTag, 
                            Banner, 
                            AdModel,
                            FooterLink,
                            Logo,
                            CompanyBanner
                            )
from apps.ad.serializers import (
                                 NavbarLinkSerializers,
                                 TrendingTagSerializer,
                                 BannerSerializer,
                                 AdSerializer,
                                 FooterLinkSerializer,
                                 LogoSerializer,
                                 CompanyBannerSerializer
                                 )


#NavbarLink Create views.

class NavbarLinkCreateView(APIView):
    serializer_class = NavbarLinkSerializers
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "NavbarLink Successfully Created"}, status=status.HTTP_200_OK)
        return Response({"message": "Failed to create NavbarLink"}, status=status.HTTP_400_BAD_REQUEST)
    
# Get All NavbarLink
  
class NavbarLinkListView(generics.ListAPIView):
    queryset = NavbarLink.objects.all().order_by('order')
    serializer_class = NavbarLinkSerializers
    
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)

#NavbarLink Retrieve Update Destroy View

class NavbarLinkRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = NavbarLink.objects.all()
    serializer_class = NavbarLinkSerializers
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "NavbarLink deleted successfully"}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "NavbarLink updated successfully", "navbarlink": response.data}, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "NavbarLink partially updated successfully", "navbarlink": response.data}, status=status.HTTP_200_OK)


#Trending tags Create Views.

class TrendingTagsCreateViews(APIView):
    serializer_class = TrendingTagSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            totalTrendingTag = TrendingTag.objects.count()
            # print("totaltag", totalTrendingTag)
            trending = TrendingTag.objects.all()
            # print(type(trending))
            if totalTrendingTag != 0 and totalTrendingTag != 1 and totalTrendingTag != 2 and totalTrendingTag != 3:
                falseFromLataesttag = trending[totalTrendingTag-4]
                # latestobj= TrendingTag.objects.get(id = falseFromLataesttag.id)
                # print("falsefromlatest", falseFromLataesttag.id)
                falseFromLataesttag.is_latest = False
                falseFromLataesttag.save()
            
            return Response({"message": "Trending Tag Successfully Created"}, status=status.HTTP_200_OK)
        return Response({"message": "Failed to create Trending Tag"}, status=status.HTTP_400_BAD_REQUEST)

# Get All Trending Tags

class TrendingTagsListView(generics.ListAPIView):
    queryset = TrendingTag.objects.all()
    serializer_class = TrendingTagSerializer

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)


class TrendingTagsRetrieveUpdateDestroyViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = TrendingTag.objects.all()
    serializer_class = TrendingTagSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "Trending tag deleted successfully"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Trending tag updated successfully", "trending_tag":response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Trending tag partially updated successfully", "trending_tag":response.data}, status=status.HTTP_200_OK)
    

# Get All Banner 

class BannerListView(generics.ListAPIView):
    queryset = Banner.objects.all()
    serializer_class = BannerSerializer

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)
    
# Banner Create Views    

class BannerCreateViews(APIView):
    serializer_class = BannerSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Banner successfully uploaded"}, status=status.HTTP_200_OK)
        return Response({"message": "Failed to upload Banner"}, status=status.HTTP_400_BAD_REQUEST)
    
# Banner Retrieve update delete view

class BannerRetrieveUpdateDestroyViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = Banner.objects.all()
    serializer_class = BannerSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "Banner deleted successfully"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Banner updated successfully", "Banner":response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Banner partially updated successfully", "Banner":response.data}, status=status.HTTP_200_OK)
    
# Get All Ad views

class AdListView(generics.ListAPIView):
    queryset = AdModel.objects.all()
    serializer_class = AdSerializer  
    
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)

# Ad Create Views    

class AdCreateViews(APIView):
    serializer_class = AdSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Ad successfully uploaded"}, status=status.HTTP_200_OK)
        return Response({"message": "Failed to upload Ad"}, status=status.HTTP_400_BAD_REQUEST)
    

class AdRetrieveUpdateDestroyViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = AdModel.objects.all()
    serializer_class = AdSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "Banner deleted successfully"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Banner updated successfully", "Banner":response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Banner partially updated successfully", "Banner":response.data}, status=status.HTTP_200_OK)

# Get All FooterLink Views

class FooterLinkListView(generics.ListAPIView):
    queryset = FooterLink.objects.all()
    serializer_class = FooterLinkSerializer

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)
    
# FooterLink Create Views   

class FooterLinkCreateViews(APIView):
    serializer_class = FooterLinkSerializer
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Footer Link successfully Created"}, status=status.HTTP_201_CREATED)
        return Response({"message": "Failed to create Footer Link"}, status=status.HTTP_400_BAD_REQUEST)


# Footer Link Retrieve Update Destroy Views

class FooterLinkRetrieveUpdateDestroyApiViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = FooterLink.objects.all()
    serializer_class = FooterLinkSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "Footer Link deleted successfully"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Footer Link updated successfully", "Footer Link":response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Footer Link partially updated successfully", "Footer Link":response.data}, status=status.HTTP_200_OK)
    

#Get All Logo

class LogoListView(generics.ListAPIView):
    queryset = Logo.objects.all()
    serializer_class = LogoSerializer
    
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)

# 
class LogoCreateView(APIView):
    serializer_class = LogoSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"Logo Successfully Created."}, status=status.HTTP_201_CREATED)
        return Response({"Failed to create logo"}, status=status.HTTP_400_BAD_REQUEST)

class LogoRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Logo.objects.all()
    serializer_class = LogoSerializer

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"Logo Successfully Deleted"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Logo Data updated successfully", "data": response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Logo Data Partially Updated", "data": response.data}, status=status.HTTP_200_OK)


#Get All Company Banner

class CompanyBannerListView(generics.ListAPIView):
    queryset = CompanyBanner.objects.all()
    serializer_class = CompanyBannerSerializer
    
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)

# Create Company Banner
class CompanyBannerCreateView(APIView):
    serializer_class = CompanyBannerSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"Company Banner Successfully Created."}, status=status.HTTP_201_CREATED)
        return Response({"Failed to create CompanyBanner"}, status=status.HTTP_400_BAD_REQUEST)

# Retrieve update delete Company Banner

class CompanyBannerRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CompanyBanner.objects.all()
    serializer_class = CompanyBannerSerializer

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"Company Banner Successfully Deleted"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Company Banner Data updated successfully", "data": response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Company Banner Data Partially Updated", "data": response.data}, status=status.HTTP_200_OK)
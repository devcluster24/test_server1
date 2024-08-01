from rest_framework import status, generics, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from apps.websiteInformation.models import About, Contact, NewsLetter
from apps.websiteInformation.serializers import (
                                                 AboutSerializer, 
                                                 ContactSerializer,
                                                 NewsLetterSerializer
                                                 ) 


# Create About Data

class AboutCreateView(views.APIView):
    serializer_class = AboutSerializer
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "About data Successfully Created"}, status=status.HTTP_201_CREATED)
        return Response({"message": "Failed to create About data"}, status=status.HTTP_400_BAD_REQUEST)


# Get All About data

class AboutListView(generics.ListAPIView):
    queryset = About.objects.all()
    serializer_class = AboutSerializer
    
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)


# About data update delete retrieve 

class AboutRetrieveUpdateDestroyViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = About.objects.all()
    serializer_class = AboutSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "About data deleted successfully"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "About data updated successfully", "data": response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "About data partially updated successfully", "data": response.data}, status=status.HTTP_200_OK)



# Create Contact Data

class ContactCreateView(views.APIView):
    serializer_class = ContactSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Contact data Successfully Created"}, status=status.HTTP_201_CREATED)
        return Response({"message": "Failed to create Contact data"}, status=status.HTTP_400_BAD_REQUEST)


# Get All Contact data

class ContactListView(generics.ListAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)


# Contact data update delete retrieve 

class ContactRetrieveUpdateDestroyViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "Contact data deleted successfully"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Contact data updated successfully", "data": response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Contact data partially updated successfully", "data": response.data}, status=status.HTTP_200_OK)


# Create NewsLetter Data

class NewsLetterCreateView(views.APIView):
    serializer_class = NewsLetterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "NewsLetter data Successfully Created"}, status=status.HTTP_201_CREATED)
        return Response({"message": "Failed to create NewsLetter data"}, status=status.HTTP_400_BAD_REQUEST)


# Get All Newsletter data

class NewsLetterListView(generics.ListAPIView):
    queryset = NewsLetter.objects.all()
    serializer_class = NewsLetterSerializer

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)


# NewsLetter data update delete retrieve 

class NewsLetterRetrieveUpdateDestroyViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = NewsLetter.objects.all()
    serializer_class = NewsLetterSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "NewsLetter data deleted successfully"}, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "NewsLetter data updated successfully", "data": response.data}, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "NewsLetter data partially updated successfully", "data": response.data}, status=status.HTTP_200_OK)
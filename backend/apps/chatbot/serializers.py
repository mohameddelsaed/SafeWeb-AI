from rest_framework import serializers
from .models import ChatSession, ChatMessage


class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ['id', 'role', 'content', 'tokens_used', 'feedback', 'action_data', 'created_at']
        read_only_fields = fields


class ChatSessionSerializer(serializers.ModelSerializer):
    messages = ChatMessageSerializer(many=True, read_only=True)
    message_count = serializers.SerializerMethodField()
    scan_id = serializers.UUIDField(source='scan_id', read_only=True, allow_null=True)

    class Meta:
        model = ChatSession
        fields = ['id', 'title', 'scan_id', 'context_type', 'message_count', 'messages', 'created_at', 'updated_at']
        read_only_fields = fields

    def get_message_count(self, obj):
        return obj.messages.count()


class ChatInputSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=2000)
    session_id = serializers.UUIDField(required=False)
    sessionId = serializers.UUIDField(required=False)
    scan_id = serializers.UUIDField(required=False)
    scanId = serializers.UUIDField(required=False)

    def validate(self, attrs):
        # Accept both camelCase and snake_case field names
        if 'sessionId' in attrs and 'session_id' not in attrs:
            attrs['session_id'] = attrs.pop('sessionId')
        elif 'sessionId' in attrs:
            attrs.pop('sessionId')
        if 'scanId' in attrs and 'scan_id' not in attrs:
            attrs['scan_id'] = attrs.pop('scanId')
        elif 'scanId' in attrs:
            attrs.pop('scanId')
        return attrs

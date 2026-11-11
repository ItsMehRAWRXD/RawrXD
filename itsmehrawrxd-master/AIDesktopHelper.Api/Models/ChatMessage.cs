using System;

namespace AIDesktopHelper.Api.Models
{
    /// <summary>
    /// Represents a chat message in the conversation
    /// </summary>
    public class ChatMessage
    {
        /// <summary>
        /// Unique identifier for the message
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// User identifier who sent the message
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// Role of the message sender (user, assistant, system)
        /// </summary>
        public string Role { get; set; }

        /// <summary>
        /// Content of the message
        /// </summary>
        public string Content { get; set; }

        /// <summary>
        /// Timestamp when the message was created
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Optional metadata for the message
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// Whether this message is part of a streaming response
        /// </summary>
        public bool IsStreaming { get; set; } = false;

        /// <summary>
        /// Token count for the message (for billing/limits)
        /// </summary>
        public int TokenCount { get; set; } = 0;
    }
}

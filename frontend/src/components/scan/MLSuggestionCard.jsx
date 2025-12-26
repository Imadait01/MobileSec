// Helper component for ML suggestions  
const MLSuggestionCard = ({ suggestion, index }) => {
    const getPriorityColor = (priority) => {
        switch (priority?.toUpperCase()) {
            case 'CRITICAL': return 'danger';
            case 'HIGH': return 'warning';
            case 'MEDIUM': return 'info';
            default: return 'default';
        }
    };

    return (
        <Card className="border border-gray-800 hover:border-green-900 transition-colors">
            <div className="flex justify-between items-start mb-4">
                <div>
                    <h3 className="text-xl font-bold text-white flex items-center gap-2">
                        <span className="text-green-400">#{suggestion.rank || index + 1}</span>
                        {suggestion.title}
                    </h3>
                    <div className="flex items-center gap-2 mt-1">
                        <Badge type={getPriorityColor(suggestion.priority)}>
                            {suggestion.priority} Priority
                        </Badge>
                        <Badge type="info">{suggestion.category}</Badge>
                    </div>
                </div>
                <Badge type={suggestion.confidence > 0.7 ? 'success' : 'warning'}>
                    {(suggestion.confidence * 100).toFixed(1)}% Confidence
                </Badge>
            </div>

            <div className="prose prose-invert max-w-none">
                <h4 className="text-gray-300 font-semibold mt-4 mb-2">Description</h4>
                <p className="text-gray-400">{suggestion.description}</p>

                {suggestion.code_example && suggestion.code_example.trim() && (
                    <>
                        <h4 className="text-gray-300 font-semibold mt-6 mb-2">Recommended Fix</h4>
                        <CodeBlock code={suggestion.code_example} />
                    </>
                )}
            </div>
        </Card>
    );
};

export { MLSuggestionCard };

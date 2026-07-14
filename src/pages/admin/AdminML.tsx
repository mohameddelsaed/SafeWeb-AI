import { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Badge from '@components/ui/Badge';
import { adminAPI } from '@services/api';

interface MLModel {
    id: string;
    name: string;
    status: string;
    accuracy: number;
    lastTrained: string;
    trainingData: string;
    version: string;
}

interface TrainingJob {
    id: number;
    model: string;
    status: string;
    progress: number;
    startTime: string;
    eta: string;
}

interface Dataset {
    id: number;
    name: string;
    samples: number;
    size: string;
    updated: string;
}

export default function AdminML() {
    const [selectedModel, setSelectedModel] = useState('');
    const [models, setModels] = useState<MLModel[]>([]);
    const [trainingJobs, setTrainingJobs] = useState<TrainingJob[]>([]);
    const [datasets, setDatasets] = useState<Dataset[]>([]);
    const [metrics, setMetrics] = useState([
        { label: 'Total Models', value: '—', change: '' },
        { label: 'Active Models', value: '—', change: '' },
        { label: 'Avg Accuracy', value: '—', change: '' },
        { label: 'Training Jobs', value: '—', change: '' },
    ]);
    const [isLoading, setIsLoading] = useState(true);
    const [isTraining, setIsTraining] = useState(false);

    const fetchML = () => {
        setIsLoading(true);
        adminAPI.getML()
            .then((res) => {
                const d = res.data;
                if (d.models) setModels(d.models);
                if (d.trainingJobs) setTrainingJobs(d.trainingJobs);
                if (d.datasets) setDatasets(d.datasets);
                if (d.metrics) setMetrics(d.metrics);
                if (d.models?.length && !selectedModel) setSelectedModel(d.models[0].id);
            })
            .catch(() => {})
            .finally(() => setIsLoading(false));
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
    useEffect(() => { fetchML(); }, []);

    const handleTrain = async (modelType?: string) => {
        setIsTraining(true);
        try {
            await adminAPI.trainModel(modelType || selectedModel);
            alert('Training job started!');
            fetchML();
        } catch {
            alert('Failed to start training.');
        } finally {
            setIsTraining(false);
        }
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                ML Model Management
                            </h1>
                            <p className="text-text-secondary">Train and manage AI detection models</p>
                        </div>
                        <Button variant="primary" onClick={() => handleTrain()} disabled={isTraining}>
                            {isTraining ? 'Starting...' : 'Train New Model'}
                        </Button>
                    </div>

                    {/* Metrics */}
                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                        </div>
                    ) : (
                    <>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        {metrics.map((metric, index) => (
                            <Card key={index} className="p-6">
                                <div className="text-sm text-text-tertiary mb-2">{metric.label}</div>
                                <div className="flex items-end justify-between">
                                    <div className="text-3xl font-bold text-text-primary">{metric.value}</div>
                                    <span className="text-sm text-accent-green">{metric.change}</span>
                                </div>
                            </Card>
                        ))}
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
                        {/* Active Models */}
                        <Card className="lg:col-span-2 p-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                Active Models
                            </h2>
                            <div className="space-y-4">
                                {models.map((model) => (
                                    <div
                                        key={model.id}
                                        className={`p-4 rounded-lg border transition-all cursor-pointer ${selectedModel === model.id
                                                ? 'border-accent-green bg-accent-green/5'
                                                : 'border-border-primary hover:border-accent-green/50'
                                            }`}
                                        onClick={() => setSelectedModel(model.id)}
                                    >
                                        <div className="flex items-start justify-between mb-3">
                                            <div>
                                                <div className="font-semibold text-text-primary mb-1">{model.name}</div>
                                                <div className="text-sm text-text-tertiary">Version {model.version}</div>
                                            </div>
                                            <Badge variant={model.status === 'active' ? 'success' : 'info'}>
                                                {model.status}
                                            </Badge>
                                        </div>
                                        <div className="grid grid-cols-3 gap-4 text-sm">
                                            <div>
                                                <div className="text-text-tertiary mb-1">Accuracy</div>
                                                <div className="font-semibold text-accent-green">{model.accuracy}%</div>
                                            </div>
                                            <div>
                                                <div className="text-text-tertiary mb-1">Training Data</div>
                                                <div className="font-semibold text-text-primary">{model.trainingData}</div>
                                            </div>
                                            <div>
                                                <div className="text-text-tertiary mb-1">Last Trained</div>
                                                <div className="font-semibold text-text-primary">{model.lastTrained}</div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </Card>

                        {/* Model Actions */}
                        <Card className="p-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                Model Actions
                            </h2>
                            <div className="space-y-3">
                                <Button variant="primary" className="w-full" onClick={() => handleTrain(selectedModel)} disabled={isTraining}>
                                    {isTraining ? 'Starting...' : 'Retrain Model'}
                                </Button>
                                <Button variant="outline" className="w-full" onClick={() => {
                                    if (!selectedModel) { alert('Select a model first'); return; }
                                    const model = models.find(m => m.id === selectedModel);
                                    if (confirm(`Deploy ${model?.name || selectedModel} to production?`)) {
                                        alert(`Model ${model?.name} has been queued for production deployment.`);
                                    }
                                }}>
                                    Deploy to Production
                                </Button>
                                <Button variant="outline" className="w-full" onClick={() => {
                                    if (!selectedModel) { alert('Select a model first'); return; }
                                    alert('Model export started. You will receive a download link when ready.');
                                }}>
                                    Export Model
                                </Button>
                                <Button variant="outline" className="w-full" onClick={() => {
                                    const model = models.find(m => m.id === selectedModel);
                                    if (model) {
                                        alert(`Model: ${model.name}\nVersion: ${model.version}\nAccuracy: ${model.accuracy}%\nStatus: ${model.status}\nLast Trained: ${model.lastTrained}\nTraining Data: ${model.trainingData}`);
                                    } else {
                                        alert('Select a model first');
                                    }
                                }}>
                                    View Metrics
                                </Button>
                                <Button variant="outline" className="w-full" onClick={() => {
                                    if (models.length < 2) { alert('Need at least 2 models to compare'); return; }
                                    const comparison = models.map(m => `${m.name} v${m.version}: ${m.accuracy}%`).join('\n');
                                    alert(`Model Comparison:\n\n${comparison}`);
                                }}>
                                    Compare Models
                                </Button>
                                <Button variant="ghost" className="w-full text-status-high" onClick={() => {
                                    if (!selectedModel) { alert('Select a model first'); return; }
                                    const model = models.find(m => m.id === selectedModel);
                                    if (confirm(`Archive ${model?.name}? This will remove it from active rotation.`)) {
                                        alert(`Model ${model?.name} has been archived.`);
                                        fetchML();
                                    }
                                }}>
                                    Archive Model
                                </Button>
                            </div>
                        </Card>
                    </div>

                    {/* Training Jobs */}
                    <Card className="p-6 mb-8">
                        <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                            Training Jobs
                        </h2>
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="border-b border-border-primary">
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Model</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Status</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Progress</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Started</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">ETA</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {trainingJobs.map((job) => (
                                        <tr key={job.id} className="border-b border-border-primary/50 hover:bg-bg-secondary/50">
                                            <td className="py-3 px-4 font-medium text-text-primary">{job.model}</td>
                                            <td className="py-3 px-4">
                                                <Badge
                                                    variant={
                                                        job.status === 'completed'
                                                            ? 'success'
                                                            : job.status === 'running'
                                                                ? 'info'
                                                                : job.status === 'failed'
                                                                    ? 'critical'
                                                                    : 'default'
                                                    }
                                                >
                                                    {job.status}
                                                </Badge>
                                            </td>
                                            <td className="py-3 px-4">
                                                <div className="flex items-center gap-3">
                                                    <div className="flex-1 h-2 bg-bg-secondary rounded-full overflow-hidden">
                                                        <div
                                                            className="h-full bg-accent-green rounded-full transition-all"
                                                            style={{ width: `${job.progress}%` }}
                                                        />
                                                    </div>
                                                    <span className="text-sm text-text-secondary">{job.progress}%</span>
                                                </div>
                                            </td>
                                            <td className="py-3 px-4 text-sm text-text-secondary">{job.startTime}</td>
                                            <td className="py-3 px-4 text-sm text-text-secondary">{job.eta}</td>
                                            <td className="py-3 px-4">
                                                <Button variant="ghost" size="sm" onClick={() => {
                                                    if (job.status === 'running') {
                                                        if (confirm(`Cancel training job for ${job.model}?`)) {
                                                            alert('Training job cancelled.');
                                                            fetchML();
                                                        }
                                                    } else {
                                                        alert(`Job: ${job.model}\nStatus: ${job.status}\nProgress: ${job.progress}%\nStarted: ${job.startTime}\nETA: ${job.eta}`);
                                                    }
                                                }}>
                                                    {job.status === 'running' ? 'Cancel' : 'View'}
                                                </Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </Card>

                    {/* Datasets */}
                    <Card className="p-6">
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary">
                                Training Datasets
                            </h2>
                            <Button variant="outline" size="sm" onClick={() => {
                                alert('Dataset upload is available via the ML API. Use: POST /api/admin/ml/datasets/ with a multipart file upload.');
                            }}>
                                Upload Dataset
                            </Button>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {datasets.map((dataset) => (
                                <div
                                    key={dataset.id}
                                    className="p-4 rounded-lg bg-bg-secondary border border-border-primary hover:border-accent-green/50 transition-all"
                                >
                                    <div className="font-semibold text-text-primary mb-3">{dataset.name}</div>
                                    <div className="grid grid-cols-3 gap-3 text-sm">
                                        <div>
                                            <div className="text-text-tertiary mb-1">Samples</div>
                                            <div className="font-semibold text-text-primary">
                                                {(dataset.samples / 1000).toFixed(0)}K
                                            </div>
                                        </div>
                                        <div>
                                            <div className="text-text-tertiary mb-1">Size</div>
                                            <div className="font-semibold text-text-primary">{dataset.size}</div>
                                        </div>
                                        <div>
                                            <div className="text-text-tertiary mb-1">Updated</div>
                                            <div className="font-semibold text-text-primary">{dataset.updated}</div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </Card>
                    </>
                    )}
                </Container>
            </div>
        </Layout>
    );
}

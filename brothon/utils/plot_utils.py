"""Plotting utilities"""
def plot_defaults():
    import matplotlib.pyplot as plt
    plt.style.use('seaborn-muted')
    plt.rc('font', size=14)
    plt.rc('xtick', labelsize=12)
    plt.rc('ytick', labelsize=12)
    plt.rc('axes', labelsize=14)
    plt.rc('axes', axisbelow=True)
    plt.rc('grid', color='grey')
    plt.rc('grid', alpha=.5)
    plt.rc('patch', linewidth=1)
    plt.rc('patch', force_edgecolor=True)
    plt.rcParams['figure.figsize'] = 10.0, 4.0
    plt.rcParams.update({'figure.autolayout': True})

def test():
    """Test the Plot Utilities"""
    plot_defaults()

if __name__ == '__main__':
    test()

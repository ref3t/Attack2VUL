import pandas as pd
import plotly.graph_objects as go

# Load the data from the CSV file
file_path = './Results/lag_counts.csv'
df = pd.read_csv(file_path)

# Create the figure
fig = go.Figure()

# Add trace for the lag data
fig.add_trace(go.Scatter(
    x=df['Lag (Days)'],
    y=df['Count'],
    mode='lines+markers',
    marker=dict(size=6, color='blue'),
    line=dict(color='blue', width=2),
    name='Attacks'
))

# Customize the layout
fig.update_layout(
    title='Number of Attacks vs. Lag (Days)',
    xaxis_title='Lag (Days)',
    yaxis_title='Number of Attacks',
    template='plotly_white',
    width=800,
    height=500,
    hovermode='closest'
)

# Show the plot
fig.show()

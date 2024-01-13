async function get_data() {
	const response = await fetch('http://127.0.0.1:32152/get_data.json');
	const data = await response.json();
	return data
}

function prep_the_graph() {
	// create an array with nodes
	let nodes = new vis.DataSet([]);

	// create an array with edges
	let edges = new vis.DataSet([]);

	// create a network
	let container = document.getElementById('mynetwork');
	let data = {
		nodes: nodes,
		edges: edges
	};
	let options = {
    physics: {
			barnesHut: {
				springLength: 200,  // The rest length of the edges
				springConstant: 0.04,  // The spring constant for the edges
				avoidOverlap: 0.1  // The amount of overlap to avoid between nodes
			}
    }
	};
	let network = new vis.Network(container, data, options);

	return [nodes, edges]
}

function update_the_graph(data, nodes, edges) {
	data.nodes.forEach(v => {
		nodes.update(v)
	})
	data.edges.forEach(v => {
		console.log(v)
		edges.update(v)
	})
}

async function process(nodes, edges) {
	let data

	setInterval(async () => {
		data = await get_data()
		update_the_graph(data, nodes, edges)
	}, 5000);
}

let [ nodes, edges ] = prep_the_graph()
process(nodes, edges)
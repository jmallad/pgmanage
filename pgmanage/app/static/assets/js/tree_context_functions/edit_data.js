/*
This file is part of OmniDB.
OmniDB is open-source software, distributed "AS IS" under the MIT license in the hope that it will be useful.

The MIT License (MIT)

Portions Copyright (c) 2015-2020, The OmniDB Team
Portions Copyright (c) 2017-2020, 2ndQuadrant Limited

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/// <summary>
/// Query state
/// </summary>
var v_editDataState = {
	Idle: 0,
	Querying: 1,
	QueryReady: 2,
  Saving: 3,
  SaveReady: 4
}

/// <summary>
/// Initiates edit data window.
/// </summary>
/// <param name="p_table">Table name.</param>
/// <param name="p_schema">Schema name.</param>
function v_startEditData(p_table,p_schema) {

	var input = JSON.stringify({"p_database_index": v_connTabControl.selectedTab.tag.selectedDatabaseIndex,
															"p_tab_id": v_connTabControl.selectedTab.id,
															"p_table" : p_table,
															"p_schema": p_schema});

	execAjax('/start_edit_data/',
			input,
			function(p_return) {

				if (p_schema)
					v_connTabControl.tag.createEditDataTab(p_schema + '.' + p_table);
				else
					v_connTabControl.tag.createEditDataTab(p_table);

				var v_currTabTag = v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag;

				if (v_currTabTag.editDataObject!=null)
					if (v_currTabTag.editor!=null) {
						 v_currTabTag.editor.destroy();
					}


				v_currTabTag.editor.setValue(p_return.v_data.v_ini_orderby);
				v_currTabTag.editor.clearSelection();

				v_currTabTag.editDataObject = new Object();
				v_currTabTag.editDataObject.editor = v_currTabTag.editor;
				v_currTabTag.editDataObject.table = p_table;
				v_currTabTag.editDataObject.schema = p_schema;
				v_currTabTag.editDataObject.firstRender = true;
				v_currTabTag.editDataObject.pk = p_return.v_data.v_pk;
				v_currTabTag.editDataObject.columns = p_return.v_data.v_cols;

				queryEditData();

			},
			function(p_return) {
				if (p_return.v_data.password_timeout) {
					showPasswordPrompt(
						v_connTabControl.selectedTab.tag.selectedDatabaseIndex,
						function() {
							v_startEditData(p_table,p_schema);
						},
						null,
						p_return.v_data.message
					);
				}
				else {
					showError(p_return.v_data)
				}
			},
			'box',
			true);

}

/// <summary>
/// Triggered when X is pressed in specific record at the edit table data window.
/// </summary>
function deleteRowEditData() {

	var v_currTabTag = v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag;
	var v_data = v_currTabTag.editDataObject.ht.getData();
	var v_row = v_currTabTag.editDataObject.ht.getSelected()[0][0];

	if (v_currTabTag.editDataObject.infoRows[v_row].mode==2) {

		v_currTabTag.editDataObject.infoRows.splice(v_row,1);
		v_data.splice(v_row,1);
		v_currTabTag.editDataObject.ht.loadData(v_data);


	}
	else {

		var v_mode = v_currTabTag.editDataObject.infoRows[v_row].mode;
		v_currTabTag.editDataObject.infoRows[v_row].mode = v_currTabTag.editDataObject.infoRows[v_row].old_mode;
		v_currTabTag.editDataObject.infoRows[v_row].old_mode = v_mode;
		v_currTabTag.editDataObject.ht.render();

	}

	v_currTabTag.button_save.style.visibility = 'visible';

}

function cancelEditData(p_tab_tag) {

	var v_tab_tag;
	if (p_tab_tag)
		v_tab_tag = p_tab_tag;
	else
		v_tab_tag = v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag;

	sendWebSocketMessage(v_queryWebSocket, v_queryRequestCodes.CancelThread, v_tab_tag.tab_id, false);

	cancelEditDataTab();

}

function cancelEditDataTab(p_tab_tag) {

	var v_tab_tag;
	if (p_tab_tag)
		v_tab_tag = p_tab_tag;
	else
		v_tab_tag = v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag;

	//Displays canceled if is querying data (not saving)
	if (v_tab_tag.state == v_editDataState.Querying)
		v_tab_tag.div_result.innerHTML = 'Canceled.';

	v_tab_tag.state = v_editDataState.Idle;
	v_tab_tag.tab_loading_span.style.visibility = 'hidden';
	v_tab_tag.tab_check_span.style.display = 'none';
	v_tab_tag.bt_cancel.style.display = 'none';

	removeContext(v_tab_tag.context.v_context_code);

	SetAcked(v_tab_tag.context);

}


function queryEditData() {

	var v_currTabTag = v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag;

	var v_state = v_currTabTag.state;

	if (v_state!=0) {
		showAlert('Tab with activity in progress.');
	}
	else {

		v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag.state = v_editDataState.Querying;
		v_currTabTag.button_save.style.visibility = 'hidden';

		var v_message_data = {
			v_table: v_currTabTag.editDataObject.table,
			v_schema: v_currTabTag.editDataObject.schema,
			v_db_index: v_connTabControl.selectedTab.tag.selectedDatabaseIndex,
			v_filter : v_currTabTag.editDataObject.editor.getValue(),
			v_count: v_currTabTag.sel_filtered_data.value,
			v_pk_list: v_currTabTag.editDataObject.pk,
			v_columns: v_currTabTag.editDataObject.columns,
			v_conn_tab_id: v_connTabControl.selectedTab.id,
			v_tab_id: v_currTabTag.tab_id
		}

		var start_time = new Date().getTime();

		v_currTabTag.tab_loading_span.style.visibility = 'visible';
		v_currTabTag.bt_cancel.style.display = '';

		var v_context = {
			tab_tag: v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag,
			start_time: new Date().getTime(),
			database_index: v_connTabControl.selectedTab.tag.selectedDatabaseIndex
		}
		v_context.tab_tag.context = v_context;

		if (v_context.tab_tag.editDataObject.ht!=null) {
			v_context.tab_tag.editDataObject.ht.destroy();
			v_context.tab_tag.editDataObject.ht = null;
		}
		v_context.tab_tag.div_result.innerHTML = 'Running...';
		v_context.tab_tag.query_info.innerHTML = '';

		//sendWebSocketMessage(v_queryWebSocket, v_queryRequestCodes.QueryEditData, v_message_data, false, v_context);
		createRequest(v_queryRequestCodes.QueryEditData, v_message_data, v_context);

		setTimeout(function() {
			if (!v_context.acked) {
				cancelEditDataTab(v_context.tab_tag);
				showAlert('No response from query server.');
			}
		},10000);

	}

}

function checkEditDataStatus(p_tab) {
	//Finished querying
	if (p_tab.tag.state == v_editDataState.QueryReady) {
		queryEditDataReturnRender(p_tab.tag.data,p_tab.tag.context);
	}
	//Finished saving
	else if (p_tab.tag.state == v_editDataState.SaveReady) {
		saveEditDataReturnRender(p_tab.tag.data,p_tab.tag.context);
	}
}


function queryEditDataReturn(p_data,p_context) {

	//If query wasn't canceled already
	if (p_context.tab_tag.state != v_editDataState.Idle) {
		p_context.duration = new Date().getTime() - p_context.start_time;

		//If tab is currently active
		if (p_context.tab_tag.tab_id == p_context.tab_tag.tabControl.selectedTab.id && p_context.tab_tag.connTab.id == p_context.tab_tag.connTab.tag.connTabControl.selectedTab.id) {
			queryEditDataReturnRender(p_data,p_context);
		}
		else {
			p_context.tab_tag.state = v_editDataState.QueryReady;
			p_context.tab_tag.context = p_context;
			p_context.tab_tag.data = p_data;

			p_context.tab_tag.tab_loading_span.style.visibility = 'hidden';
			p_context.tab_tag.tab_check_span.style.display = '';

		}
	}
}

function queryEditDataReturnRender(p_message,p_context) {
	p_context.tab_tag.state = v_editDataState.Idle;
	p_context.tab_tag.context = null;
	p_context.tab_tag.data = null;

	var v_data = p_message.v_data;
	var v_currTabTag = p_context.tab_tag;

	var v_div_result = v_currTabTag.div_result;
	var v_query_info = v_currTabTag.query_info;

	if (v_currTabTag.editDataObject.ht!=null) {
		v_currTabTag.editDataObject.ht.destroy();
		v_currTabTag.editDataObject.ht = null;
	}

	v_div_result.innerHTML = '';

	var request_time = p_context.duration;

	if (p_message.v_error) {

		v_div_result.innerHTML = '<div class="error_text">' + p_message.v_data + '</div>';
		v_query_info.innerHTML = "Response time: " + request_time/1000 + " seconds";

	}
	else {

		if (v_currTabTag.editDataObject.pk.length==0) {
			if (v_currTabTag.editDataObject.firstRender)
				showAlert('Table has no primary key, existing rows will be read only.');

			v_currTabTag.editDataObject.firstRender = false;
			v_currTabTag.editDataObject.hasPK = false;
		}
		else
			v_currTabTag.editDataObject.hasPK = true;

		window.scrollTo(0,0);

		v_query_info.innerHTML = "<span style='font-weight: 900; color: #4a81d4;'>" + v_data.v_query_info +  "</span><span> rows</span><span> in </span><span style='font-weight: 900; color: #4a81d4;'>" + request_time/1000 + "</span><span> seconds</span>";

		var columnProperties = [];

		var col = new Object();
		col.title = ' ';
		col.width = 40;
		columnProperties.push(col);

		for (var i = 0; i < v_currTabTag.editDataObject.columns.length; i++) {
				var col = new Object();

				var v_tooltip_attr =
				' data-toggle=tooltip ' +
				'data-placement=bottom ' +
				'data-html=true ' +
				'title="<div><b>Type</b> ' + v_currTabTag.editDataObject.columns[i].v_type + '</div>" ';

				var v_tooltip_html = '<i class="ml-1 omnidb__theme-icon--primary fas fa-info-circle"' + v_tooltip_attr + '"></i>';

				if (!v_currTabTag.editDataObject.columns[i].v_is_pk)
					col.title =  '<span>' + v_currTabTag.editDataObject.columns[i].v_column + '</span>' + v_tooltip_html;
				else
					col.title = '<i class="fas fa-key action-key text-secondary"></i> <span>' + v_currTabTag.editDataObject.columns[i].v_column + '</span>' + v_tooltip_html;

				col.renderer = 'text';
			columnProperties.push(col);

		}

		var v_infoRows = [];

						for (var i=0; i < v_data.v_data.length; i++) {
							var v_object = new Object();
							v_object.mode = 0;
							v_object.old_mode = -1;
							v_object.index = i;
							v_object.changed_cols = [];
							v_object.pk = v_data.v_row_pk[i];
							v_infoRows.push(v_object);
						}

		var v_div_result = v_currTabTag.div_result;

		if (v_div_result.innerHTML!='') {

			v_currTabTag.editDataObject.ht.destroy();
		}

		v_currTabTag.editDataObject.infoRows = v_infoRows;

		var container = v_div_result;
		v_currTabTag.editDataObject.ht = new Handsontable(container,
		{
			licenseKey: 'non-commercial-and-evaluation',
			columns : columnProperties,
			data : v_data.v_data,
			colHeaders : true,
			rowHeaders : true,
			manualColumnResize: true,
			fixedColumnsLeft: 1,
			minSpareRows: 1,
			contextMenu: {
					callback: function (key, options) {
						if (key === 'edit_data') {
							if (v_currTabTag.editDataObject.hasPK)
								cellDataModal(this,options[0].start.row,options[0].start.col,this.getDataAtCell(options[0].start.row,options[0].start.col),true);
							else
								cellDataModal(this,options[0].start.row,options[0].start.col,this.getDataAtCell(options[0].start.row,options[0].start.col),false);
						}
						else if (key === 'copy') {
							this.selectCell(options[0].start.row,options[0].start.col,options[0].end.row,options[0].end.col);
							document.execCommand('copy');
						}
					},
					items: {
						"copy": {name: '<div style=\"position: absolute;\"><i class=\"fas fa-copy cm-all\" style=\"vertical-align: middle;\"></i></div><div style=\"padding-left: 30px;\">Copy</div>'},
						"edit_data": {name: '<div style=\"position: absolute;\"><i class=\"fas fa-edit cm-all\" style=\"vertical-align: middle;\"></i></div><div style=\"padding-left: 30px;\">Edit Content</div>'}
					}
				},
			beforeChange: function (changes, source) {
										if (!changes) {
												return;
										}

										$.each(changes, function (index, element) {
												var change = element;
												var rowIndex = change[0];
												var columnIndex = change[1];
												var oldValue = change[2];
												var newValue = change[3];

												if (rowIndex >= v_currTabTag.editDataObject.infoRows.length)
												{
													var v_object = new Object();
								v_object.mode = 2;
								v_object.old_mode = -1;
								v_object.changed_cols = [];
								v_object.index = v_currTabTag.editDataObject.infoRows.length;
								v_object.pk = null;

						v_currTabTag.editDataObject.infoRows.push(v_object);

						v_currTabTag.button_save.style.visibility = 'visible';

												}
												if(oldValue != newValue && v_currTabTag.editDataObject.infoRows[rowIndex].mode!=2){

													var v_found = false;

													if (v_currTabTag.editDataObject.infoRows[rowIndex].changed_cols.indexOf(columnIndex-1)==-1) {
													v_currTabTag.editDataObject.infoRows[rowIndex].changed_cols.push(columnIndex-1);
												}


													if (v_currTabTag.editDataObject.infoRows[rowIndex].mode!=-1) {
														v_currTabTag.editDataObject.infoRows[rowIndex].mode = 1;

													}
													else
														v_currTabTag.editDataObject.infoRows[rowIndex].old_mode = 1;

														v_currTabTag.button_save.style.visibility = 'visible';

												}
										});
								},
								cells: function (row, col, prop) {

									var cellProperties = {};


					if (v_currTabTag.editDataObject.infoRows[row]!=null) {

						if (!v_currTabTag.editDataObject.hasPK && v_currTabTag.editDataObject.infoRows[row].mode!=2) {
							if (col==0)
								cellProperties.renderer = grayEmptyRenderer;
							else
								cellProperties.renderer = grayRenderer;
							cellProperties.readOnly = true;
						}
						else if (col==0) {
							cellProperties.renderer = editDataActionRenderer;
							cellProperties.readOnly = true;
					}
						else if (v_currTabTag.editDataObject.infoRows[row].mode==2) {
							cellProperties.renderer = greenRenderer;
						}
						else if (v_currTabTag.editDataObject.infoRows[row].mode==-1) {
							cellProperties.renderer = redRenderer;
						}
						else if (v_currTabTag.editDataObject.infoRows[row].mode==1) {
							cellProperties.renderer = yellowRenderer;
						}
						else {
							cellProperties.renderer = whiteRenderer;
							// if (row % 2 == 0) {
							// 	cellProperties.renderer = blueRenderer;
							// }
							// else {
							// 	cellProperties.renderer = whiteRenderer;
							// }
						}

				}
				else {
					if (col==0) {
							cellProperties.renderer = newRowRenderer;
							cellProperties.readOnly = true;
					}
				}

					return cellProperties;

			}
		});

	}

	p_context.tab_tag.tab_loading_span.style.visibility = 'hidden';
	p_context.tab_tag.tab_check_span.style.display = 'none';
	p_context.tab_tag.bt_cancel.style.display = 'none';

	$('[data-toggle="tooltip"]').tooltip({animation:true});// Loads or Updates all tooltips

}

function saveEditData() {

	let currTabTag = v_connTabControl.selectedTab.tag.tabControl.selectedTab.tag;

	var state = currTabTag.state;

	if (state != v_editDataState.Idle) {
		showAlert('Tab with activity in progress.');
	}
	else {

		currTabTag.state = v_editDataState.Saving;
		currTabTag.button_save.style.visibility = 'hidden';

		let changedRowsInfo = [];
		let changedRowsData = [];

		currTabTag.editDataObject.infoRows.forEach((row, index) => {
			if(row.mode !== 0) {
				row.index = index
				changedRowsInfo.push(row)
				// the first row element is sliced out
				// since it has the delete button and does not hold any data
				changedRowsData.push(currTabTag.editDataObject.ht.getDataAtRow(index).slice(1));
			}
		})

		var message_data = {
			v_table: currTabTag.editDataObject.table,
			v_schema: currTabTag.editDataObject.schema,
			v_db_index: v_connTabControl.selectedTab.tag.selectedDatabaseIndex,
			v_data_rows : changedRowsData,
			v_rows_info: changedRowsInfo,
			v_pk_info: currTabTag.editDataObject.pk,
			v_columns: currTabTag.editDataObject.columns,
			v_conn_tab_id: v_connTabControl.selectedTab.id,
			v_tab_id: currTabTag.tab_id
		}

		currTabTag.tab_loading_span.style.visibility = 'visible';
		currTabTag.bt_cancel.style.display = '';

		let v_context = {
			tab_tag: currTabTag,
			start_time: new Date().getTime()
		}
		v_context.tab_tag.context = v_context;

		v_context.tab_tag.query_info.innerHTML = '';

		//sendWebSocketMessage(v_queryWebSocket, v_queryRequestCodes.SaveEditData, v_message_data, false, v_context);
		createRequest(v_queryRequestCodes.SaveEditData, message_data, v_context);

	}
}

function saveEditDataReturn(p_data,p_context) {

	//If query wasn't canceled already
	if (p_context.tab_tag.state != v_editDataState.Idle) {
		p_context.duration = new Date().getTime() - p_context.start_time;

		//If tab is currently active
		if (p_context.tab_tag.tab_id == p_context.tab_tag.tabControl.selectedTab.id && p_context.tab_tag.connTab.id == p_context.tab_tag.connTab.tag.connTabControl.selectedTab.id) {
			saveEditDataReturnRender(p_data,p_context);
		}
		else {
			p_context.tab_tag.state = v_editDataState.SaveReady;
			p_context.tab_tag.context = p_context;
			p_context.tab_tag.data = p_data;

			p_context.tab_tag.tab_loading_span.style.visibility = 'hidden';
			p_context.tab_tag.tab_check_span.style.display = '';

		}
	}
}

function saveEditDataReturnRender(p_message,p_context) {
	p_context.tab_tag.state = v_editDataState.Idle;
	p_context.tab_tag.context = null;
	p_context.tab_tag.data = null;

	var v_data = p_message.v_data;
	var v_currTabTag = p_context.tab_tag;

	var v_div_result = v_currTabTag.div_result;
	var v_query_info = v_currTabTag.query_info;

	var request_time = p_context.duration;
	v_query_info.innerHTML = "Save time: " + request_time/1000 + " seconds";

	//var v_div_commands_log = document.getElementById('div_commands_log_list');
	//v_div_commands_log.innerHTML = '';
	var v_commands_log = '';

	var v_has_error = false;

	v_currTabTag.button_save.style.visibility = 'hidden';

	for (var i = v_data.length-1; i >= 0; i--) {

		if (v_data[i].mode==-1) {
			if (!v_data[i].error) {

				v_currTabTag.editDataObject.infoRows.splice(v_data[i].index, 1);
				v_currTabTag.editDataObject.ht.alter('remove_row', v_data[i].index);

			}
			else {

				v_has_error = true;

				v_commands_log += '<b>Command:</b> ' + v_data[i].command + '<br/><br/><b>Message:</b><br><br><div class="error_text">' + v_data[i].v_message + '</div><br/><br/>';

				v_currTabTag.button_save.style.visibility = 'visible';
			}
		}
		else if (v_data[i].mode==2) {
			if (!v_data[i].error) {

				v_currTabTag.editDataObject.infoRows[v_data[i].index].mode = 0;
				v_currTabTag.editDataObject.infoRows[v_data[i].index].old_mode = -1;
				v_currTabTag.editDataObject.infoRows[v_data[i].index].changed_cols = [];

				//Creating pk
				var v_pk_list = [];

				for (var j = 0; j < v_currTabTag.editDataObject.pk.length; j++) {

					var v_pk = { v_column: v_currTabTag.editDataObject.pk[j].v_column,
								 v_value : v_currTabTag.editDataObject.ht.getDataAtCell(v_data[i].index, v_currTabTag.editDataObject.pk[j].v_index + 1)
								 };
						v_pk_list.push(v_pk);
				}

				v_currTabTag.editDataObject.infoRows[v_data[i].index].pk = v_pk_list;

			}
			else {

				v_has_error = true;

				v_commands_log += '<b>Command:</b> ' + v_data[i].command + '<br/><br/><b>Message:</b><br><br><div class="error_text">' + v_data[i].v_message  + '</div><br/><br/>';

				v_currTabTag.button_save.style.visibility = 'visible';
			}
		}
		else if (v_data[i].mode==1) {
			if (!v_data[i].error) {

				v_currTabTag.editDataObject.infoRows[v_data[i].index].mode = 0;
				v_currTabTag.editDataObject.infoRows[v_data[i].index].old_mode = -1;
				v_currTabTag.editDataObject.infoRows[v_data[i].index].changed_cols = [];

				//Creating pk
				var v_pk_list = [];

				for (var j = 0; j < v_currTabTag.editDataObject.pk.length; j++) {

					var v_pk = { v_column: v_currTabTag.editDataObject.pk[j].v_column,
								 v_value : v_currTabTag.editDataObject.ht.getDataAtCell(v_data[i].index, v_currTabTag.editDataObject.pk[j].v_index + 1)
								 };
						v_pk_list.push(v_pk);
				}

				v_currTabTag.editDataObject.infoRows[v_data[i].index].pk = v_pk_list;

			}
			else {

				v_has_error = true;

				v_commands_log += '<b>Command:</b> ' + v_data[i].command + '<br/><br/><b>Message:</b><br><br><div class="error_text">' + v_data[i].v_message  + '</div><br/><br/>';

				v_currTabTag.button_save.style.visibility = 'visible';
			}
		}
v_currTabTag.bt_cancel.style.display = '';
	}

	if (v_has_error) {
		//v_div_commands_log.innerHTML = v_commands_log;
		//$('#div_commands_log').addClass('isActive');
		showAlert(v_commands_log)

	}

	v_currTabTag.editDataObject.ht.render();


	p_context.tab_tag.tab_loading_span.style.visibility = 'hidden';
	p_context.tab_tag.tab_check_span.style.display = 'none';
	p_context.tab_tag.bt_cancel.style.display = 'none';

}

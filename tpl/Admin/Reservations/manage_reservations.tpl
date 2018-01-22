{*
Copyright 2011-2017 Nick Korbel

This file is part of Booked Scheduler.

Booked Scheduler is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Booked Scheduler is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Booked Scheduler.  If not, see <http://www.gnu.org/licenses/>.
*}

{include file='globalheader.tpl' Qtip=true InlineEdit=true}

<div id="page-manage-reservations" class="admin-page">
	<div>
		<div class="dropdown admin-header-more pull-right">
			<button class="btn btn-default" type="button" id="moreReservationActions" data-toggle="dropdown">
				<span class="glyphicon glyphicon-option-horizontal"></span>
				<span class="caret"></span>
			</button>
			<ul class="dropdown-menu" role="menu" aria-labelledby="moreReservationActions">
				{if $CanViewAdmin}
					<li role="presentation">
						<a role="menuitem" href="#" id="import-reservations" class="add-link">{translate key=Import}
							<span class="glyphicon glyphicon-import"></span>
						</a>
					</li>
				{/if}
				<li role="presentation">
					<a role="menuitem" href="{$CsvExportUrl}" download="{$CsvExportUrl}" class="add-link" target="_blank">{translate key=Export}
						<span class="glyphicon glyphicon-export"></span>
					</a>
				</li>
			</ul>
		</div>
		<h1>{translate key=ManageReservations}</h1>
	</div>

	<div class="panel panel-default filterTable" id="filter-reservations-panel">
		<div class="panel-heading"><span class="glyphicon glyphicon-filter"></span> {translate key="Filter"} {showhide_icon}</div>
		<div class="panel-body">
			{assign var=groupClass value="col-xs-12 col-sm-4 col-md-3"}
			<form id="filterForm" class="form-inline" role="form">
				<div class="form-group filter-dates {$groupClass}">
					<input id="startDate" type="text" class="form-control dateinput inline"
						   value="{formatdate date=$StartDate}"/>
					<input id="formattedStartDate" type="hidden" value="{formatdate date=$StartDate key=system}"/>
					-
					<input id="endDate" type="text" class="form-control dateinput inline"
						   value="{formatdate date=$EndDate}"/>
					<input id="formattedEndDate" type="hidden" value="{formatdate date=$EndDate key=system}"/>
				</div>
				<div class="form-group filter-user {$groupClass}">
					<input id="userFilter" type="text" class="form-control" value="{$UserNameFilter}"
						   placeholder="{translate key=User}"/>
					<input id="userId" type="hidden" value="{$UserIdFilter}"/>
				</div>
				<div class="form-group filter-schedule {$groupClass}">
					<select id="scheduleId" class="form-control">
						<option value="">{translate key=AllSchedules}</option>
						{object_html_options options=$Schedules key='GetId' label="GetName" selected=$ScheduleId}
					</select>
				</div>
				<div class="form-group filter-resource {$groupClass}">
					<select id="resourceId" class="form-control">
						<option value="">{translate key=AllResources}</option>
						{object_html_options options=$Resources key='GetId' label="GetName" selected=$ResourceId}
					</select>
				</div>
				<div class="form-group filter-status {$groupClass}">
					<select id="statusId" class="form-control">
						<option value="">{translate key=AllReservations}</option>
						<option value="{ReservationStatus::Pending}"
								{if $ReservationStatusId eq ReservationStatus::Pending}selected="selected"{/if}>{translate key=PendingReservations}</option>
					</select>
				</div>
				<div class="form-group filter-referenceNumber {$groupClass}">
					<input id="referenceNumber" type="text" class="form-control" value="{$ReferenceNumber}"
						   placeholder="{translate key=ReferenceNumber}"/>
				</div>
				<div class="form-group filter-resourceStatus {$groupClass}">
					<select id="resourceStatusIdFilter" class="form-control">
						<option value="">{translate key=AllResourceStatuses}</option>
						<option value="{ResourceStatus::AVAILABLE}">{translate key=Available}</option>
						<option value="{ResourceStatus::UNAVAILABLE}">{translate key=Unavailable}</option>
						<option value="{ResourceStatus::HIDDEN}">{translate key=Hidden}</option>
					</select>
				</div>
				<div class="form-group filter-resourceStatusReason {$groupClass}">
					<select id="resourceReasonIdFilter" class="form-control"></select>
				</div>
				<div class="clearfix"></div>
				{foreach from=$AttributeFilters item=attribute}
					{control type="AttributeControl" attribute=$attribute searchmode=true class="customAttribute filter-customAttribute{$attribute->Id()} {$groupClass}"}
				{/foreach}
			</form>
		</div>
		<div class="panel-footer">
			{filter_button id="filter" class="btn-sm"}
			{reset_button id="clearFilter" class="btn-sm"}
		</div>
	</div>

	<table class="table admin-panel" id="reservationTable">
		{assign var=colCount value=11}
		<thead>
		<tr>
			<th class="id hidden">&nbsp;</th>
			<th>{sort_column key=User field=ColumnNames::OWNER_LAST_NAME}</th>
			<th>{sort_column key=Resource field=ColumnNames::RESOURCE_NAME}</th>
			<th>{sort_column key=Title field=ColumnNames::RESERVATION_TITLE}</th>
			<th>{sort_column key=Description field=ColumnNames::RESERVATION_DESCRIPTION}</th>
			<th>{sort_column key=BeginDate field=ColumnNames::RESERVATION_START}</th>
			<th>{sort_column key=EndDate field=ColumnNames::RESERVATION_END}</th>
			<th>{translate key='Duration'}</th>
			<th>{translate key='ReferenceNumber'}</th>
			{if $CreditsEnabled}
				<th>{translate key='Credits'}</th>
				{assign var=colCount value=$colCount+1}
			{/if}
			{if !$IsDesktop}
				<th class="action">{translate key='Edit'}</th>
				{assign var=colCount value=$colCount+1}
			{/if}
			<th class="action">{translate key='Approve'}</th>
			<th class="action">{translate key='Delete'}</th>
			<th class="action-delete">
				<div class="checkbox checkbox-single">
					<input type="checkbox" id="delete-all" aria-label="{translate key=All}"/>
					<label for="delete-all"></label>
				</div>
			</th>
		</tr>
		</thead>
		<tbody>
		{foreach from=$reservations item=reservation}
			{cycle values='row0,row1' assign=rowCss}
			{if $reservation->RequiresApproval}
				{assign var=rowCss value='pending'}
			{/if}
			{assign var=reservationId value=$reservation->ReservationId}
			<tr class="{$rowCss} {if $IsDesktop}editable{/if}" data-seriesId="{$reservation->SeriesId}" data-refnum="{$reservation->ReferenceNumber}">
				<td class="id hidden">{$reservationId}</td>
				<td class="user">{fullname first=$reservation->FirstName last=$reservation->LastName ignorePrivacy=true}</td>
				<td class="resource">{$reservation->ResourceName}
					{if $reservation->ResourceStatusId == ResourceStatus::AVAILABLE}
						{html_image src="status.png"}
						{*{translate key='Available'}*}
					{elseif $reservation->ResourceStatusId == ResourceStatus::UNAVAILABLE}
						{html_image src="status-away.png"}
						{*{translate key='Unavailable'}*}
					{else}
						{html_image src="status-busy.png"}
						{*{translate key='Hidden'}*}
					{/if}
					{*{if array_key_exists($reservation->ResourceStatusReasonId,$StatusReasons)}*}
					{*<span class="reservationResourceStatusReason">{$StatusReasons[$reservation->ResourceStatusReasonId]->Description()}</span>*}
					{*{/if}*}
				</td>
				<td class="reservationTitle">{$reservation->Title}</td>
				<td class="description">{$reservation->Description}</td>
				<td class="date">{formatdate date=$reservation->StartDate timezone=$Timezone key=short_reservation_date}</td>
				<td class="date">{formatdate date=$reservation->EndDate timezone=$Timezone key=short_reservation_date}</td>
				<td class="duration">{$reservation->GetDuration()->__toString()}</td>
				<td class="referenceNumber">{$reservation->ReferenceNumber}</td>
				{if $CreditsEnabled}
					<td class="credits">{$reservation->CreditsConsumed}</td>
				{/if}
				{if !$IsDesktop}
					<td class="action">
						<a href="#" class="update edit"><span class="fa fa-pencil icon fa-1x"></span></a>
					</td>
				{/if}
				<td class="action">
					{if $reservation->RequiresApproval}
						<a href="#" class="update approve"><span class="fa fa-check icon add"></span></a>
					{else}
						-
					{/if}
				</td>
				<td class="action">
					<a href="#" class="update delete"><span class="fa fa-trash icon remove fa-1x"></span></a>
				</td>
				<td class="action-delete no-edit">
					<div class="checkbox checkbox-single">
						<input {formname key=RESERVATION_ID multi=true}" class="delete-multiple" type="checkbox" id="delete{$reservationId}"
						value="{$reservationId}"
						aria-label="{translate key=Delete}"/>
						<label for="delete{$reservationId}"></label>
					</div>
				</td>
			</tr>
			<tr class="{$rowCss}" data-seriesId="{$reservation->SeriesId}" data-refnum="{$reservation->ReferenceNumber}">
				<td colspan="{$colCount}">
					<div class="reservation-list-dates">
						<div>
							<label>{translate key='Created'}</label> {formatdate date=$reservation->CreatedDate timezone=$Timezone key=short_datetime}
						</div>
						<div>
							<label>{translate key='LastModified'}</label> {formatdate date=$reservation->ModifiedDate timezone=$Timezone key=short_datetime}
						</div>
						<div>
							<label>{translate key='CheckInTime'}</label> {formatdate date=$reservation->CheckinDate timezone=$Timezone key=short_datetime}
						</div>
						<div>
							<label>{translate key='CheckOutTime'}</label> {formatdate date=$reservation->CheckoutDate timezone=$Timezone key=short_datetime}
						</div>
						<div>
							<label>{translate key='OriginalEndDate'}</label> {formatdate date=$reservation->OriginalEndDate timezone=$Timezone key=short_datetime}
						</div>
					</div>
					{if $ReservationAttributes|count > 0}
						<div class="reservation-list-attributes">
							{foreach from=$ReservationAttributes item=attribute}
								{include file='Admin/InlineAttributeEdit.tpl'
								id=$reservation->ReferenceNumber attribute=$attribute
								value=$reservation->Attributes->Get($attribute->Id())
								url="{$smarty.server.SCRIPT_NAME}?action={ManageReservationsActions::UpdateAttribute}"
								}
							{/foreach}
						</div>
					{/if}

				</td>
			</tr>
		{/foreach}
		</tbody>
		<tfoot>
		<tr>
			<td colspan="{$colCount-1}"></td>
			<td class="action-delete"><a href="#" id="delete-selected" class="no-show" title="{translate key=Delete}"><span class="fa fa-trash icon remove"></span></a></td>
		</tr>
		</tfoot>
	</table>

	{pagination pageInfo=$PageInfo}

	<div class="modal fade" id="deleteInstanceDialog" tabindex="-1" role="dialog"
		 aria-labelledby="deleteInstanceDialogLabel" aria-hidden="true">
		<div class="modal-dialog">
			<form id="deleteInstanceForm" method="post">
				<div class="modal-content">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="deleteInstanceDialogLabel">{translate key=Delete}</h4>
					</div>
					<div class="modal-body">
						<div class="delResResponse"></div>
						<div class="alert alert-warning">
							{translate key=DeleteWarning}
						</div>

						<input type="hidden" {formname key=SERIES_UPDATE_SCOPE}
							   value="{SeriesUpdateScope::ThisInstance}"/>
						<input type="hidden" {formname key=REFERENCE_NUMBER} value="" class="referenceNumber"/>
					</div>
					<div class="modal-footer">
						{cancel_button}
						{delete_button}
						{indicator}
					</div>
				</div>
			</form>
		</div>
	</div>

	<div class="modal fade" id="deleteSeriesDialog" tabindex="-1" role="dialog"
		 aria-labelledby="deleteSeriesDialogLabel"
		 aria-hidden="true">
		<div class="modal-dialog">
			<form id="deleteSeriesForm" method="post">
				<div class="modal-content">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="deleteSeriesDialogLabel">{translate key=Delete}</h4>
					</div>
					<div class="modal-body">
						<div class="alert alert-warning">
							{translate key=DeleteWarning}
						</div>
						<input type="hidden" id="hdnSeriesUpdateScope" {formname key=SERIES_UPDATE_SCOPE} />
						<input type="hidden" {formname key=REFERENCE_NUMBER} value="" class="referenceNumber"/>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-default cancel"
								data-dismiss="modal">{translate key='Cancel'}</button>

						<button type="button" class="btn btn-danger saveSeries btnUpdateThisInstance" id="btnUpdateThisInstance">
							{translate key='ThisInstance'}
						</button>
						<button type="button" class="btn btn-danger saveSeries btnUpdateAllInstances" id="btnUpdateAllInstances">
							{translate key='AllInstances'}
						</button>
						<button type="button" class="btn btn-danger saveSeries btnUpdateFutureInstances" id="btnUpdateFutureInstances">
							{translate key='FutureInstances'}
						</button>
						{indicator}
					</div>
				</div>
			</form>
		</div>
	</div>

	<div id="deleteMultipleDialog" class="modal fade" tabindex="-1" role="dialog" aria-labelledby="deleteMultipleModalLabel"
		 aria-hidden="true">
		<form id="deleteMultipleForm" method="post" ajaxAction="{ManageReservationsActions::DeleteMultiple}">
			<div class="modal-dialog">
				<div class="modal-content">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="deleteMultipleModalLabel">{translate key=Delete} (<span id="deleteMultipleCount"></span>)</h4>
					</div>
					<div class="modal-body">
						<div class="alert alert-warning">
							<div>{translate key=DeleteWarning}</div>

							<div>{translate key=DeleteMultipleReservationsWarning}</div>
						</div>

					</div>
					<div class="modal-footer">
						{cancel_button}
						{delete_button}
						{indicator}
					</div>
					<div id="deleteMultiplePlaceHolder" class="no-show"></div>
				</div>
			</div>
		</form>
	</div>

	<div id="inlineUpdateErrorDialog" class="modal fade" tabindex="-1" role="dialog" aria-labelledby="inlineErrorLabel"
		 aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content">
				<div class="modal-header">
					<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
					<h4 class="modal-title" id="inlineErrorLabel">{translate key=Error}</h4>
				</div>
				<div class="modal-body">
					<div id="inlineUpdateErrors" class="hidden error">&nbsp;</div>
					<div id="reservationAccessError" class="hidden error"></div>
				</div>
				<div class="modal-footer">
					<button type="button" class="btn btn-default cancel"
							data-dismiss="modal">{translate key='OK'}</button>
				</div>
			</div>
		</div>
	</div>

	<div id="importReservationsDialog" class="modal" tabindex="-1" role="dialog" aria-labelledby="importReservationsModalLabel"
		 aria-hidden="true">
		<form id="importReservationsForm" class="form" role="form" method="post" enctype="multipart/form-data"
			  ajaxAction="{ManageReservationsActions::Import}">
			<div class="modal-dialog">
				<div class="modal-content">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="importReservationsModalLabel">{translate key=Import}</h4>
					</div>
					<div class="modal-body">
						<div id="importUserResults" class="validationSummary alert alert-danger no-show">
							<ul>
								{async_validator id="fileExtensionValidator" key=""}
							</ul>
						</div>
						<div id="importErrors" class="alert alert-danger no-show"></div>
						<div id="importResult" class="alert alert-success no-show">
							<span>{translate key=RowsImported}</span>

							<div id="importCount" class="inline bold">0</div>
							<span>{translate key=RowsSkipped}</span>

							<div id="importSkipped" class="inline bold">0</div>
							<a class="" href="{$smarty.server.SCRIPT_NAME}">{translate key=Done} <span
										class="fa fa-refresh"></span></a>
						</div>
						<div class="margin-bottom-25">
							<input type="file" {formname key=RESERVATION_IMPORT_FILE} />
						</div>
						<div id="importInstructions" class="alert alert-info">
							<div class="note">{translate key=ReservationImportInstructions}</div>
							<a href="{$smarty.server.SCRIPT_NAME}?dr=template" download="{$smarty.server.SCRIPT_NAME}?dr=template"
							   target="_blank">{translate key=GetTemplate} <span class="fa fa-download"></span></a>
						</div>
					</div>
					<div class="modal-footer">
						{cancel_button}
						{add_button key=Import}
						{indicator}
					</div>
				</div>
			</div>
		</form>
	</div>

    {include file="javascript-includes.tpl" Qtip=true InlineEdit=true}
	{jsfile src="ajax-helpers.js"}
	{jsfile src="admin/reservations.js"}

	{jsfile src="autocomplete.js"}
	{jsfile src="reservationPopup.js"}
	{jsfile src="approval.js"}

	<script type="text/javascript">

		function hidePopoversWhenClickAway() {
			$('body').on('click', function (e) {
				$('[rel="popover"]').each(function () {
					if (!$(this).is(e.target) && $(this).has(e.target).length === 0 && $('.popover').has(e.target).length === 0)
					{
						$(this).popover('hide');
					}
				});
			});
		}

		function setUpPopovers() {
			$('[rel="popover"]').popover({
				container: 'body', html: true, placement: 'top', content: function () {
					var popoverId = $(this).data('popover-content');
					return $(popoverId).html();
				}
			}).click(function (e) {
				e.preventDefault();
			}).on('show.bs.popover', function () {

			}).on('shown.bs.popover', function () {
				var trigger = $(this);
				var popover = trigger.data('bs.popover').tip();
				popover.find('.editable-cancel').click(function () {
					trigger.popover('hide');
				});
			});
		}

		function setUpEditables() {
			$.fn.editable.defaults.mode = 'popup';
			$.fn.editable.defaults.toggle = 'manual';
			$.fn.editable.defaults.emptyclass = '';
			$.fn.editable.defaults.params = function (params) {
				params.CSRF_TOKEN = $('#csrf_token').val();
				return params;
			};

			var updateUrl = '{$smarty.server.SCRIPT_NAME}?action=';

			$('.inlineAttribute').editable({
				url: updateUrl + '{ManageReservationsActions::UpdateAttribute}', emptytext: '-'
			});
		}

		$(document).ready(function () {

			setUpPopovers();
			hidePopoversWhenClickAway();
			setUpEditables();

			var updateScope = {};
			updateScope['btnUpdateThisInstance'] = '{SeriesUpdateScope::ThisInstance}';
			updateScope['btnUpdateAllInstances'] = '{SeriesUpdateScope::FullSeries}';
			updateScope['btnUpdateFutureInstances'] = '{SeriesUpdateScope::FutureInstances}';

			var actions = {};

			var resOpts = {
				autocompleteUrl: "{$Path}ajax/autocomplete.php?type={AutoCompleteType::User}",
				reservationUrlTemplate: "{$Path}reservation.php?{QueryStringKeys::REFERENCE_NUMBER}=[refnum]",
				popupUrl: "{$Path}ajax/respopup.php",
				updateScope: updateScope,
				actions: actions,
				deleteUrl: '{$Path}ajax/reservation_delete.php?{QueryStringKeys::RESPONSE_TYPE}=json',
				resourceStatusUrl: '{$smarty.server.SCRIPT_NAME}?{QueryStringKeys::ACTION}=changeStatus',
				submitUrl: '{$smarty.server.SCRIPT_NAME}'
			};

			var approvalOpts = {
				url: '{$Path}ajax/reservation_approve.php'
			};

			var approval = new Approval(approvalOpts);

			var reservationManagement = new ReservationManagement(resOpts, approval);
			reservationManagement.init();

			{foreach from=$reservations item=reservation}

			reservationManagement.addReservation({
				id: '{$reservation->ReservationId}',
				referenceNumber: '{$reservation->ReferenceNumber}',
				isRecurring: '{$reservation->IsRecurring}',
				resourceStatusId: '{$reservation->ResourceStatusId}',
				resourceStatusReasonId: '{$reservation->ResourceStatusReasonId}',
				resourceId: '{$reservation->ResourceId}'
			});
			{/foreach}

			{foreach from=$StatusReasons item=reason}
			reservationManagement.addStatusReason('{$reason->Id()}', '{$reason->StatusId()}', '{$reason->Description()|escape:javascript}');
			{/foreach}

			reservationManagement.initializeStatusFilter('{$ResourceStatusFilterId}', '{$ResourceStatusReasonFilterId}');
		});

		$('#filter-reservations-panel').showHidePanel();

	</script>

	{control type="DatePickerSetupControl" ControlId="startDate" AltId="formattedStartDate"}
	{control type="DatePickerSetupControl" ControlId="endDate" AltId="formattedEndDate"}

	{csrf_token}

	<div id="colorbox">
		<div id="approveDiv" class="wait-box">
			<h3>{translate key=Approving}</h3>
			{html_image src="reservation_submitting.gif"}
		</div>
	</div>

</div>

{include file='globalfooter.tpl'}